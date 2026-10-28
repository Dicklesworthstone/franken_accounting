//! The canonical immutable entry (plan §4.2, §4.6, Appendix A `fa:entry:v1`).
//!
//! One vertex carries the whole accounting fact: ordered legs inline, the
//! proposal every approval binds, and the envelope that commits it. Two
//! digests:
//!
//! - `proposal_digest = BLAKE3("fa:entry-proposal:v1" ‖ canonical(proposal))`
//!   over every field except the envelope fields (`plan_certificate_oid`,
//!   `approvals`) and the two digests;
//! - `entry_digest   = BLAKE3("fa:entry:v1" ‖ proposal_digest ‖ canonical(plan_certificate_oid) ‖ canonical(approvals))`,
//!   the committed envelope.
//!
//! The graph is acyclic by construction: the dry-run certificate is computed
//! over a plan that contains `proposal_digest`, so its oid can only live in
//! the envelope; approvals bind `proposal_digest`, never `entry_digest`.
//! Changing one leg changes `proposal_digest`, so an approval no longer binds
//! and the commit is refused (FA-INV-10).
//!
//! Erasable fields are committed by their full wire bytes (digest, subject,
//! nonce, ciphertext), which erasure never changes. A *semantic* transcript
//! — the same encoding with each erasable field replaced by its opened
//! plaintext — exists only in memory for the kernel's retry decision
//! (`EntryPayload::semantic_digest`); it is never stored or logged.
//!
//! What this module checks is *structure*: bounds, class/leg shape, sorted
//! collections, consistent `unit_totals`, digest integrity. The accounting
//! laws (balance per unit, leaf-only, period admissibility, evidence minima)
//! belong to the kernel's laws step and are not re-derived here.

use core::fmt;

use fa_money::{Amount, Side, UnitId};
use fa_time::DateDay;
use fgdb_crypto::Hasher;
use fgdb_types::VId;

use crate::canon::{DecodeError, EncodeError, Reader, Writer, strictly_ascending};
use crate::erasable::{Canonical, Erasable, EraseError, SealKey};
use crate::ids::{ApprovalRef, EntryRef, Id128, Oid, PeriodRef, TypedRef};
use crate::limits::*;

pub const SCHEMA_MAJOR: u16 = 1;
/// The highest additive minor this reader understands in full. Minor 0 is
/// the original layout; minor 1 appends the extension block, and minor 2
/// admits the named proportional-post basis, and minor 3 admits the
/// prior-period-adjustment source period. A writer may
/// emit any minor ≤ this; bytes at a higher minor decode with their unknown
/// extension tags preserved and skipped.
pub const SCHEMA_MINOR: u16 = 3;
/// The first minor whose layout carries the trailing extension block.
pub const EXTENSIONS_MINOR: u16 = 1;
pub const PROPOSAL_DIGEST_DOMAIN: &[u8] = b"fa:entry-proposal:v1";
pub const ENTRY_DIGEST_DOMAIN: &[u8] = b"fa:entry:v1";
pub const SEMANTIC_DIGEST_DOMAIN: &[u8] = b"fa:entry-semantic:v1";
/// Extension tag 1, `fa:balancing:v1` (plan §5.5): the balancing request of
/// a two-leg entry — `leg: u16 LE ‖ requested mantissa: i128 LE` (18 bytes).
/// The legs carry the amount that moved; the identity of the post binds this
/// request (fa-journal `limit::post_balancing`).
pub const BALANCING_EXTENSION: u16 = 1;
/// Extension tag 2, `fa:auto-reverse:v1` (plan §7.6, Appendix B `Accrue` /
/// `Defer`): an `Adjusting` entry's scheduled reversal —
/// `reverse_on: i32 LE (DateDay) ‖ rule: u8` (5 bytes; rule 1 = exact
/// negation). The proposal digest covers it, so the original approvals bind
/// the date and the rule (fa-journal `schedule`).
pub const AUTO_REVERSE_EXTENSION: u16 = 2;
/// Extension tag 3, `fa:effective-date-basis:v1` (plan §7.7): how a
/// kernel-minted entry's effective date was derived from an instant —
/// `policy: u8 ‖ tick_ref: u128 LE` (17 bytes; policy 1 = Utc). Only the
/// kernel records it, on scheduled reversals.
pub const DATE_BASIS_EXTENSION: u16 = 3;
/// Extension tag 4, `fa:legal-hold-scope:v1` (plan §8.5; fa-txf): a
/// `HoldControl` entry's scope beside its `HoldEvent`, which carries only the
/// scope's digest. On a Place: `0u8 ‖ list(u128 subject)`, strictly
/// ascending, or, for a book-scope Place, `2u8 ‖ u64 through` (every entry,
/// document and party recorded at or before `through`; fa-k07b). On a
/// Release: `1u8 ‖ u128 hold`, the Place it releases.
pub const LEGAL_HOLD_SCOPE_EXTENSION: u16 = 4;
/// Extension tag 5, `fa:allocation-posting:v1` (plan §6.3; fa-joq): an
/// `Allocation` entry's computation binding — the driver basis's canonical
/// bytes, law digest and basis digest
/// (`registries/object_schemas/allocation.toml`). fa-journal `allocation`
/// interprets it in full. Format v2 binds an ordered destination account and
/// dimension map; v1 retains its original shared-dimension encoding.
pub const ALLOCATION_EXTENSION: u16 = 5;
/// Extension tag 6, `fa:event-ref:v1` (plan §4.1 `Event`, §4.5, FA-INV-05,
/// bead `fa-f3bo`): binds an `EntryProposal` to a committed REA `Event`
/// vertex — `event_vid: u128 LE ‖ event_digest: [u8; 32]` (48 bytes).
pub const EVENT_REF_EXTENSION: u16 = 6;
/// Extension tag 7, `fa:capability-body:v1` (plan §14.2, bead fa-v62): the
/// canonical bytes of the capability a `PolicyControl` issuance journals.
/// Its `CapabilityEvent.commitment` is the commitment of exactly these bytes,
/// so the kernel derives an issued token's caveats from the journal, never
/// from the presenter.
pub const CAPABILITY_BODY_EXTENSION: u16 = 7;
/// Extension tag 8, `fa:draft-body:v1` (plan §15.2, Appendix A `DraftSet`,
/// bead fa-s7x): a draft's immutable body on its `DraftControl` Open
/// record — `u16 version ‖ book_id[16] ‖ str name ‖ u128 owner_principal`.
pub const DRAFT_BODY_EXTENSION: u16 = 8;
/// Extension tag 9, `fa:draft-intent` (bead fa-s7x): one planned intent
/// on a draft's `DraftControl` Plan record — `u16 version ‖ bytes
/// post_intent ‖ bytes capability`: the intent's canonical bytes and the
/// planner's capability, which its promotion replays. Version 2 appends the
/// exact resolved Entry digest `[32]` reviewed in ordered draft rehearsal;
/// version 3 also appends `bytes resolved_entry`, preserving the original
/// target for dependent retries after discard or availability drift. Empty
/// resolved bytes denote the Entry exactly sealed from the retained proposal
/// and approvals (no plan certificate), verified against the retained digest.
/// Version 4 retains an atomic batch as `u16 4 | bytes batch_key | list(bytes
/// v3_member)`: one ordered group of reviewed intents under one capability.
/// Every member is appended by the same control publication; promotion still
/// replays the complete draft in order. Version 5 retains a dedicated atomic
/// correction as `u16 5 | bytes v3_reversal | bytes v3_replacement`: the same
/// target and planner, exact reviewed entries, and native paired publication.
/// Versions 1--4 keep their original encoding.
pub const DRAFT_INTENT_EXTENSION: u16 = 9;
/// Extension tag 10, `fa:scenario-body:v1` (plan §15.2, Appendix B
/// `ForkScenario`, bead fa-k07b): a scenario's immutable body on its
/// `ScenarioControl` Open record — `u16 version ‖ book_id[16] ‖ str name ‖
/// u128 owner_principal ‖ u64 fork_at ‖ u8 has_from ‖ [i32 from_day]`.
pub const SCENARIO_BODY_EXTENSION: u16 = 10;
/// Extension tag 11, `fa:scenario-intent:v1` (bead fa-k07b): one
/// counterfactual intent on a scenario's `ScenarioControl` Plan record —
/// `u16 version ‖ bytes post_intent ‖ bytes capability`. It never posts to
/// trunk; every materialization posts it into a scratch replay.
pub const SCENARIO_INTENT_EXTENSION: u16 = 11;
/// Extension tag 12, the intrinsic YearEndClose v1 source and routing basis.
/// The kernel recomputes its complete fold on every Closing admission.
pub const YEAR_END_CLOSE_EXTENSION: u16 = 12;
/// Extension tag 13, `fa:production-profile:v1` (plan §13.2, Appendix A
/// `ProductionProfile`, bead fa-6l9): a matter's immutable production
/// profile on its `ProductionControl` Open record — `u16 version ‖
/// book_id[16] ‖ str matter ‖ str bates_prefix ‖ u64 first_bates ‖ u8
/// load_file_format ‖ opt oid protective_order`.
pub const PRODUCTION_PROFILE_EXTENSION: u16 = 13;
/// Extension tag 14, `fa:production-bates:v1` (bead fa-6l9): the Bates ranges
/// one `ProductionControl` Produce record assigns in its matter — `u16
/// version ‖ str matter ‖ list(oid document ‖ [32] doc_commit ‖ u64 start ‖
/// u64 end ‖ u8 designation)`, in production order.
pub const PRODUCTION_BATES_EXTENSION: u16 = 14;
/// Extension tag 15, `fa:statement-issuance:v1` (plan §12.5, Appendix A
/// `StatementIssuance`, bead fa-wrrw): what one `IssuanceControl` record
/// says left the entity — `u16 version ‖ book_id[16] ‖ str period ‖ [32]
/// definition_digest ‖ str definition_name ‖ u32 definition_version ‖ [32]
/// certificate ‖ u64 certified_at ‖ u8 issued_to ‖ opt oid document`.
pub const STATEMENT_ISSUANCE_EXTENSION: u16 = 15;
/// Extension tag 16, the complete source and route basis for intrinsic
/// period-end FX revaluation. New native admissions reproduce this basis.
pub const FX_REVALUATION_EXTENSION: u16 = 16;
/// Extension tag 17, `fa:engagement:v1` (plan §11.12, Appendix A
/// `Engagement`, bead fa-zgn): an engagement's immutable profile on its
/// `EngagementControl` Open record — `u16 version ‖ book_id[16] ‖ str
/// engagement ‖ u8 kind ‖ u128 firm_principal ‖ list(str period) ‖ u32 unit
/// ‖ i128 overall ‖ i128 performance ‖ i128 clearly_trivial ‖ opt i32
/// report_release_day ‖ [32] capability_commitment`.
pub const ENGAGEMENT_PROFILE_EXTENSION: u16 = 17;
/// Extension tag 18, `fa:proposed-adjustment:v1` (bead fa-zgn): the draft
/// correcting entry one `EngagementControl` Propose record journals — `u16
/// version ‖ str engagement ‖ u32 ordinal ‖ i32 effective_day ‖ list(u8
/// side ‖ u128 account ‖ u32 unit ‖ i128 mantissa)`, balanced per unit; its
/// description rides the record's sealed description. It never posts.
pub const PROPOSED_ADJUSTMENT_EXTENSION: u16 = 18;
/// Extension tag 19, `fa:restatement-case:v1` (plan §8.3, Appendix A
/// `RestatementCase`, bead fa-75j4): a case's immutable body on its
/// `CaseControl` Open record — `u16 version ‖ book_id[16] ‖ u32 ordinal ‖
/// u8 kind ‖ list(str period) ‖ opt oid narrative ‖ opt (i32 day ‖ oid
/// authority)`.
pub const RESTATEMENT_CASE_EXTENSION: u16 = 19;
/// Extension tag 20, `fa:case-determination:v1` (bead fa-75j4): the
/// determination a `CaseControl` Determine record journals — `u16 version
/// ‖ i32 day ‖ oid authority`.
pub const CASE_DETERMINATION_EXTENSION: u16 = 20;
/// Extension tag 21, `fa:case-rehearsal:v1` (bead fa-75j4): the rehearsal a
/// `CaseControl` Rehearse record journals — `u16 version ‖ str scenario ‖
/// [32] certificate ‖ u64 fork_at ‖ list(str period) ‖ list(u128 plan)`:
/// the scenario the correction was rehearsed on, the digest of its retained
/// diff certificate, the trunk sequence it forked at, the periods the diff
/// covers and the scenario's Plan records it covers, in planning order.
pub const CASE_REHEARSAL_EXTENSION: u16 = 21;
/// Extension tag 22, `fa:case-approval:v1` (bead fa-75j4): the effect
/// manifest a `CaseControl` Approve record's approvals bind — `u16 version
/// ‖ u128 case ‖ [32] body digest ‖ [32] rehearsal digest ‖ list(u128 plan ‖
/// [32] intent digest ‖ u128 planner)`.
pub const CASE_APPROVAL_EXTENSION: u16 = 22;
/// Extension tag 23, `fa:case-member:v1` (bead fa-75j4): on a posting entry
/// a restatement case posts, the case and the Plan record it derives from —
/// `u16 version ‖ u32 case ordinal ‖ u128 plan record`. Only the kernel's
/// derivation of an Approved case's manifest entry carries it.
pub const CASE_MEMBER_EXTENSION: u16 = 23;
/// Extension tag 24, `fa:case-posted:v1` (bead fa-75j4): the entries a
/// `CaseControl` Post record names — `u16 version ‖ list(u128 plan ‖ u128
/// entry ‖ [32] entry digest)`, in manifest order.
pub const CASE_POSTED_EXTENSION: u16 = 24;
/// Extension tag 25, `fa:case-disclosure:v1` (bead fa-75j4): on a
/// `CaseControl` Disclose record, the Disclosure document the case is
/// disclosed in and the Reviewed attestation over it — `u16 version ‖
/// [32] document oid ‖ u128 attestation`.
pub const CASE_DISCLOSURE_EXTENSION: u16 = 25;
/// Extension tag 26, `fa:documentation-completion:v1` (plan §11.12, AS
/// 1215.15, bead fa-zgn): on an `EngagementControl` Complete record, the
/// report release date and the documentation completion date — `u16
/// version ‖ i32 report_release_day ‖ i32 completion_day`.
pub const DOCUMENTATION_COMPLETION_EXTENSION: u16 = 26;
/// Extension tag 27, `fa:prior-period-error:v1` (plan §8.2, §11.12, bead
/// fa-zgn): an `Adjusting` entry that corrects an immaterial prior-period
/// error in the current period, without a case, and the earlier period the
/// error belongs to — `u16 version ‖ str calendar ‖ str period code`. The
/// proposal digest covers it; the summary of uncorrected misstatements
/// counts the entry's effect on current-period income (SAB 108 rollover).
pub const PRIOR_PERIOD_ERROR_EXTENSION: u16 = 27;
/// Extension tag 28, `fa:engagement-carry-forward:v1` (plan §11.12, SAB 108,
/// bead fa-zgn): on an `EngagementControl` CarryForward record, the prior
/// engagement whose uncorrected misstatements carry into this one, and the
/// auditor's statement of which of them reversed through this period's
/// income and which an out-of-period correction here corrected — `u16
/// version ‖ u128 prior engagement ‖ list(u32 turned-around ordinal) ‖
/// list(u32 corrected ordinal)`, each list strictly ascending, disjoint.
pub const ENGAGEMENT_CARRY_FORWARD_EXTENSION: u16 = 28;

/// Extension tag 29, the approved fixed template and execution capability of a
/// monthly recurring schedule (plan §7.6). The whole body is approval-bound.
pub const RECURRING_SCHEDULE_EXTENSION: u16 = 29;
/// Extension tag 30, the complete canonical external-detail Workpaper whose
/// gross account/unit/dimension/side fold this Original summary posts.
pub const EXTERNAL_SUBLEDGER_EXTENSION: u16 = 30;
/// Extension tag 31, a kernel-minted recurring occurrence: version, schedule,
/// zero-based occurrence index and the committed TimeEvidence tick.
pub const RECURRING_OCCURRENCE_EXTENSION: u16 = 31;
/// `fa:rule-inputs:v1`: a rule-derived entry's inputs in Canon's canonical
/// bytes (`fa_canon::encode_inputs`), so its derivation can be re-run
/// (plan §10.3, FA-INV-05 `rule-reproduction`).
pub const RULE_INPUTS_EXTENSION: u16 = 32;
/// Extension tag 33, `fa:obligation-maturity:v1` (plan §11.6, bead fa-5dpd):
/// when the obligations this entry books on its credit legs fall due
/// ([`crate::obligation::InlineObligationTerms`]); validated against the
/// legs by [`crate::obligation::validate_terms`].
pub const OBLIGATION_MATURITY_EXTENSION: u16 = 33;
/// Extension tag 34, `fa:valuation-adjustment:v1` (plan §11.6, bead fa-8j3g):
/// explicit dated valuation inputs this entry carries
/// ([`crate::valuation::InlineValuationTerms`]); validated by
/// [`crate::valuation::validate_terms`].
pub const VALUATION_ADJUSTMENT_EXTENSION: u16 = 34;

/// Extension 35, `fa:proportional-post:v1`: the exact named law and rate
/// of a Resolution(Posts), recomputed against its authenticated hold.
pub const PROPORTIONAL_POST_EXTENSION: u16 = 35;
pub const PROPORTIONAL_POST_SCHEMA_MINOR: u16 = 2;

/// Extension 36, `fa:prior-period-adjustment:v1`: the historical period
/// whose error a case corrects through opening retained earnings. The
/// marker also rides an Original/Adjusting scenario template, so the
/// rehearsal and the case's approved derivation bind the same period.
pub const PRIOR_PERIOD_ADJUSTMENT_EXTENSION: u16 = 36;
pub const PRIOR_PERIOD_ADJUSTMENT_SCHEMA_MINOR: u16 = 3;

/// The immutable source-period claim of a prior-period adjustment.
/// Accounting admission checks the period, case and retained-earnings
/// accounts; this codec checks only its bounded, versioned representation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PriorPeriodAdjustment {
    pub relates_to: PeriodRef,
}

impl PriorPeriodAdjustment {
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.u16(1);
        self.relates_to.encode(&mut w);
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        if r.u16("prior_period_adjustment.version")? != 1 {
            return Err(r.invalid("prior_period_adjustment.version"));
        }
        let relates_to = PeriodRef::decode(&mut r)?;
        if relates_to.calendar.is_empty() || relates_to.code.is_empty() {
            return Err(r.invalid("prior_period_adjustment.relates_to"));
        }
        r.finish()?;
        Ok(Self { relates_to })
    }
}

/// Extension tags this reader understands. A payload at a higher
/// `schema_minor` may carry others; they are preserved and skipped.
pub const KNOWN_EXTENSION_TAGS: &[u16] = &[
    BALANCING_EXTENSION,
    AUTO_REVERSE_EXTENSION,
    DATE_BASIS_EXTENSION,
    LEGAL_HOLD_SCOPE_EXTENSION,
    ALLOCATION_EXTENSION,
    EVENT_REF_EXTENSION,
    CAPABILITY_BODY_EXTENSION,
    DRAFT_BODY_EXTENSION,
    DRAFT_INTENT_EXTENSION,
    SCENARIO_BODY_EXTENSION,
    SCENARIO_INTENT_EXTENSION,
    YEAR_END_CLOSE_EXTENSION,
    PRODUCTION_PROFILE_EXTENSION,
    PRODUCTION_BATES_EXTENSION,
    STATEMENT_ISSUANCE_EXTENSION,
    FX_REVALUATION_EXTENSION,
    ENGAGEMENT_PROFILE_EXTENSION,
    PROPOSED_ADJUSTMENT_EXTENSION,
    RESTATEMENT_CASE_EXTENSION,
    CASE_DETERMINATION_EXTENSION,
    CASE_REHEARSAL_EXTENSION,
    CASE_APPROVAL_EXTENSION,
    CASE_MEMBER_EXTENSION,
    CASE_POSTED_EXTENSION,
    CASE_DISCLOSURE_EXTENSION,
    DOCUMENTATION_COMPLETION_EXTENSION,
    PRIOR_PERIOD_ERROR_EXTENSION,
    ENGAGEMENT_CARRY_FORWARD_EXTENSION,
    RECURRING_SCHEDULE_EXTENSION,
    EXTERNAL_SUBLEDGER_EXTENSION,
    RECURRING_OCCURRENCE_EXTENSION,
    RULE_INPUTS_EXTENSION,
    OBLIGATION_MATURITY_EXTENSION,
    VALUATION_ADJUSTMENT_EXTENSION,
    PROPORTIONAL_POST_EXTENSION,
    PRIOR_PERIOD_ADJUSTMENT_EXTENSION,
];

// ---------------------------------------------------------------------------
// Entry classes (registries/entry_classes.toml, compiled)
// ---------------------------------------------------------------------------

/// A registered entry class tag. The constants mirror
/// `registries/entry_classes.toml`; `code_classes_match_registry` is the gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntryClass(pub u16);

impl EntryClass {
    pub const ORIGINAL: Self = Self(1);
    pub const PENDING: Self = Self(2);
    pub const RESOLUTION: Self = Self(3);
    pub const REVERSAL: Self = Self(4);
    pub const REPLACEMENT: Self = Self(5);
    pub const RECLASSIFICATION: Self = Self(6);
    pub const ADJUSTING: Self = Self(7);
    pub const CLOSING: Self = Self(8);
    pub const ALLOCATION: Self = Self(9);
    pub const REVALUATION: Self = Self(10);
    pub const ELIMINATION: Self = Self(11);
    pub const MIGRATION: Self = Self(12);
    pub const REVISION: Self = Self(13);
    pub const RESTATEMENT: Self = Self(14);
    pub const PRIOR_PERIOD_ADJUSTMENT: Self = Self(15);
    pub const PERIOD_CONTROL: Self = Self(16);
    pub const SCHEMA_CONTROL: Self = Self(17);
    pub const POLICY_CONTROL: Self = Self(18);
    pub const TIME_CONTROL: Self = Self(19);
    pub const SWEEP_CONTROL: Self = Self(20);
    pub const SCHEDULE_CONTROL: Self = Self(21);
    /// A `MigrationRun`'s lifecycle (plan §8.6): Open, Finalize, Abandon.
    pub const MIGRATION_CONTROL: Self = Self(22);
    /// An `ImportRun` receipt (plan §9.3): book-scoped, undated.
    pub const IMPORT_CONTROL: Self = Self(23);
    /// A legal hold or its release (plan §8.5): book-scoped, undated.
    pub const HOLD_CONTROL: Self = Self(24);
    /// A `DraftSet`'s lifecycle (plan §15.2): Open, Plan, Promote, Discard.
    /// Book-scoped, undated; nothing in a draft is a trunk entry.
    pub const DRAFT_CONTROL: Self = Self(25);
    /// A `Scenario`'s lifecycle (plan §15.2, bead fa-k07b): Open, Plan,
    /// Discard. Book-scoped, undated; a scenario never posts to trunk.
    pub const SCENARIO_CONTROL: Self = Self(26);
    /// A matter's litigation production (plan §13.2, bead fa-6l9): Open (its
    /// `ProductionProfile`), Produce (the Bates ranges a production assigns).
    /// Book-scoped, undated; a Bates number is never reassigned.
    pub const PRODUCTION_CONTROL: Self = Self(27);
    /// A statement package leaving the entity (plan §12.5, bead fa-wrrw):
    /// one `StatementIssuance` per record. Book-scoped, undated; an issuance
    /// is never withdrawn, and the first one per period is what `AS
    /// ORIGINALLY REPORTED` reads.
    pub const ISSUANCE_CONTROL: Self = Self(28);
    /// An audit engagement's mechanics (plan §11.12, bead fa-zgn): Open (its
    /// `Engagement` with stated materiality parameters), Propose (a draft
    /// correcting entry), Book (the committed entry that corrects it), Pass
    /// (left uncorrected, with its reason). Book-scoped, undated; nothing
    /// in it alters a committed amount.
    pub const ENGAGEMENT_CONTROL: Self = Self(29);
    /// A `RestatementCase`'s life cycle (plan §8.3, bead fa-75j4): Open,
    /// Determine, and the later Rehearse, Approve, Post, Disclose, Close.
    /// Book-scoped, undated; the case makes a material correction legal.
    pub const CASE_CONTROL: Self = Self(30);

    /// `(tag, name, is_control)` for every registered class.
    pub const ALL: &[(u16, &str, bool)] = &[
        (1, "Original", false),
        (2, "Pending", false),
        (3, "Resolution", false),
        (4, "Reversal", false),
        (5, "Replacement", false),
        (6, "Reclassification", false),
        (7, "Adjusting", false),
        (8, "Closing", false),
        (9, "Allocation", false),
        (10, "Revaluation", false),
        (11, "Elimination", false),
        (12, "Migration", false),
        (13, "Revision", false),
        (14, "Restatement", false),
        (15, "PriorPeriodAdjustment", false),
        (16, "PeriodControl", true),
        (17, "SchemaControl", true),
        (18, "PolicyControl", true),
        (19, "TimeControl", true),
        (20, "SweepControl", true),
        (21, "ScheduleControl", true),
        (22, "MigrationControl", true),
        (23, "ImportControl", true),
        (24, "HoldControl", true),
        (25, "DraftControl", true),
        (26, "ScenarioControl", true),
        (27, "ProductionControl", true),
        (28, "IssuanceControl", true),
        (29, "EngagementControl", true),
        (30, "CaseControl", true),
    ];

    #[must_use]
    pub fn name(self) -> Option<&'static str> {
        Self::ALL
            .iter()
            .find(|(t, _, _)| *t == self.0)
            .map(|(_, n, _)| *n)
    }

    #[must_use]
    pub fn is_registered(self) -> bool {
        self.name().is_some()
    }

    #[must_use]
    pub fn is_control(self) -> bool {
        Self::ALL.iter().any(|(t, _, c)| *t == self.0 && *c)
    }

    /// Whether posted legs of this class carry open-item balances (plan §5.7;
    /// cross-checked against `registries/entry_classes.toml` by
    /// `code_classes_match_registry`).
    ///
    /// Control classes, `Pending` holds (which reserve without posting), and
    /// `Reversal` entries (which negate their target rather than opening a
    /// new item) do not carry open items; all other registered posting
    /// classes do when they carry legs.
    #[must_use]
    pub fn carries_open_items(self) -> bool {
        self.is_registered()
            && !self.is_control()
            && !matches!(self, Self::PENDING | Self::REVERSAL)
    }

    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .find(|(_, n, _)| *n == name)
            .map(|(t, _, _)| Self(*t))
    }
}

// ---------------------------------------------------------------------------
// Control kinds (the [[control_kind]] table of registries/entry_classes.toml)
// ---------------------------------------------------------------------------

/// A registered `EntryOrigin::Control.control_kind`: the act that minted a
/// control record (fa-g23). The constants mirror the `[[control_kind]]` rows
/// of `registries/entry_classes.toml` (`code_control_kinds_match_registry`
/// is the gate). The id is private: outside this crate a kind exists only
/// as a registered constant, an origin naming an unregistered id does not
/// decode, and `entry_mirrors` refuses to stage a record whose kind mints
/// another class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ControlKind(u16);

impl ControlKind {
    pub const CHART_INSTALL: Self = Self(1);
    pub const PERIOD_TRANSITION: Self = Self(2);
    pub const POLICY_ACTIVATION: Self = Self(3);
    pub const TIME_TICK: Self = Self(4);
    pub const SCHEDULE_CANCEL: Self = Self(5);
    pub const IMPORT_RUN: Self = Self(6);
    pub const LEGAL_HOLD: Self = Self(7);
    pub const CAPABILITY_REVOCATION: Self = Self(8);
    pub const MIGRATION_RUN: Self = Self(9);
    pub const CAPABILITY_ISSUANCE: Self = Self(10);
    pub const DRAFT_TRANSITION: Self = Self(11);
    pub const SCENARIO_TRANSITION: Self = Self(12);
    pub const PERIOD_CREATION: Self = Self(13);
    pub const PRODUCTION_TRANSITION: Self = Self(14);
    pub const STATEMENT_ISSUANCE: Self = Self(15);
    pub const ENGAGEMENT_TRANSITION: Self = Self(16);
    pub const CASE_TRANSITION: Self = Self(17);
    pub const RECURRING_SCHEDULE: Self = Self(18);
    /// A Canon rule version activated from a date (plan §10.3, fa-c34).
    pub const RULE_ACTIVATION: Self = Self(19);

    /// Every registered kind: `(kind, name, the control class it mints)`.
    pub const ALL: &'static [(Self, &'static str, EntryClass)] = &[
        (
            Self::CHART_INSTALL,
            "chart_install",
            EntryClass::SCHEMA_CONTROL,
        ),
        (
            Self::PERIOD_TRANSITION,
            "period_transition",
            EntryClass::PERIOD_CONTROL,
        ),
        (
            Self::POLICY_ACTIVATION,
            "policy_activation",
            EntryClass::POLICY_CONTROL,
        ),
        (Self::TIME_TICK, "time_tick", EntryClass::TIME_CONTROL),
        (
            Self::SCHEDULE_CANCEL,
            "schedule_cancel",
            EntryClass::SCHEDULE_CONTROL,
        ),
        (Self::IMPORT_RUN, "import_run", EntryClass::IMPORT_CONTROL),
        (Self::LEGAL_HOLD, "legal_hold", EntryClass::HOLD_CONTROL),
        (
            Self::CAPABILITY_REVOCATION,
            "capability_revocation",
            EntryClass::POLICY_CONTROL,
        ),
        (
            Self::MIGRATION_RUN,
            "migration_run",
            EntryClass::MIGRATION_CONTROL,
        ),
        (
            Self::CAPABILITY_ISSUANCE,
            "capability_issuance",
            EntryClass::POLICY_CONTROL,
        ),
        (
            Self::DRAFT_TRANSITION,
            "draft_transition",
            EntryClass::DRAFT_CONTROL,
        ),
        (
            Self::SCENARIO_TRANSITION,
            "scenario_transition",
            EntryClass::SCENARIO_CONTROL,
        ),
        (
            Self::PERIOD_CREATION,
            "period_creation",
            EntryClass::SCHEMA_CONTROL,
        ),
        (
            Self::PRODUCTION_TRANSITION,
            "production_transition",
            EntryClass::PRODUCTION_CONTROL,
        ),
        (
            Self::STATEMENT_ISSUANCE,
            "statement_issuance",
            EntryClass::ISSUANCE_CONTROL,
        ),
        (
            Self::ENGAGEMENT_TRANSITION,
            "engagement_transition",
            EntryClass::ENGAGEMENT_CONTROL,
        ),
        (
            Self::CASE_TRANSITION,
            "case_transition",
            EntryClass::CASE_CONTROL,
        ),
        (
            Self::RECURRING_SCHEDULE,
            "recurring_schedule",
            EntryClass::SCHEDULE_CONTROL,
        ),
        (
            Self::RULE_ACTIVATION,
            "rule_activation",
            EntryClass::POLICY_CONTROL,
        ),
    ];

    /// The registered kind with this id, if any.
    #[must_use]
    pub fn from_id(id: u16) -> Option<Self> {
        Self::ALL
            .iter()
            .find(|(k, _, _)| k.0 == id)
            .map(|(k, _, _)| *k)
    }

    #[must_use]
    pub fn id(self) -> u16 {
        self.0
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        Self::ALL
            .iter()
            .find(|(k, _, _)| *k == self)
            .map_or("", |(_, n, _)| *n)
    }

    /// The control class this kind mints.
    #[must_use]
    pub fn class(self) -> Option<EntryClass> {
        Self::ALL
            .iter()
            .find(|(k, _, _)| *k == self)
            .map(|(_, _, c)| *c)
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EntryError {
    Decode(DecodeError),
    Encode(EncodeError),
    /// A structural rule the payload violates; `what` names the field and `why` the rule.
    Invalid {
        what: &'static str,
        why: &'static str,
    },
    /// `unit_totals` does not equal the fold over the legs.
    TotalsMismatch,
    /// A sum of leg mantissas overflowed `i128`.
    Overflow,
    /// A stored digest does not match its recomputation.
    DigestMismatch {
        which: &'static str,
    },
    /// The encoded payload exceeds `max_entry_bytes`.
    TooLarge {
        bytes: usize,
        max: usize,
    },
    /// A sealed field could not be opened for the semantic transcript.
    Sealed(EraseError),
}

impl fmt::Display for EntryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "{e}"),
            Self::Encode(e) => write!(f, "{e}"),
            Self::Invalid { what, why } => write!(f, "`{what}`: {why}"),
            Self::TotalsMismatch => write!(f, "unit_totals do not equal the fold over the legs"),
            Self::Overflow => write!(f, "a sum of leg amounts overflowed"),
            Self::DigestMismatch { which } => write!(f, "{which} does not match its recomputation"),
            Self::TooLarge { bytes, max } => {
                write!(f, "payload is {bytes} bytes; max_entry_bytes is {max}")
            }
            Self::Sealed(e) => write!(f, "sealed field: {e}"),
        }
    }
}

impl core::error::Error for EntryError {}

impl From<DecodeError> for EntryError {
    fn from(e: DecodeError) -> Self {
        Self::Decode(e)
    }
}

impl From<EncodeError> for EntryError {
    fn from(e: EncodeError) -> Self {
        Self::Encode(e)
    }
}

fn invalid(what: &'static str, why: &'static str) -> EntryError {
    EntryError::Invalid { what, why }
}

// ---------------------------------------------------------------------------
// Encoding sinks: the wire form, or the private semantic transcript
// ---------------------------------------------------------------------------

/// How erasable fields are written. `Wire` writes their committed bytes;
/// `Plain` opens each one under `key` and writes the plaintext instead,
/// recording the first failure. `Plain` output exists only in memory.
enum Sink<'a> {
    Wire,
    Plain {
        key: &'a SealKey,
        failed: Option<EraseError>,
    },
}

impl Sink<'_> {
    fn erasable<T: Canonical>(&mut self, w: &mut Writer, e: &Erasable<T>, max: usize) {
        match self {
            Self::Wire => e.encode(w),
            Self::Plain { key, failed } => match e.open(key, max) {
                Ok(v) => {
                    // The subject context is part of the meaning: the same
                    // plaintext under two subjects is two different requests.
                    w.u8(1).opt(e.subject_ref().as_ref(), |w, s| {
                        w.u128(s.0);
                    });
                    v.write_canonical(w);
                }
                Err(err) => {
                    if failed.is_none() {
                        *failed = Some(err);
                    }
                }
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

fn encode_amount(w: &mut Writer, a: &Amount) {
    w.u32(a.unit.0).i128(a.mantissa);
}

fn decode_amount(r: &mut Reader<'_>) -> Result<Amount, DecodeError> {
    Ok(Amount::new(
        UnitId(r.u32("amount.unit")?),
        r.i128("amount.mantissa")?,
    ))
}

fn encode_oid(w: &mut Writer, o: &Oid) {
    w.fixed(&o.0);
}

fn decode_oid(r: &mut Reader<'_>, what: &'static str) -> Result<Oid, DecodeError> {
    Ok(Oid(r.fixed(what)?))
}

fn encode_day(w: &mut Writer, d: &DateDay) {
    w.i32(d.0);
}

fn decode_day(r: &mut Reader<'_>, what: &'static str) -> Result<DateDay, DecodeError> {
    Ok(DateDay(r.i32(what)?))
}

/// A settlement application target (plan §5.3 `settles`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settlement {
    pub target: EntryRef,
    pub ordinal: u16,
    pub amount: Amount,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegPayload {
    pub side: Side,
    pub account_ref: VId,
    pub amount: Amount,
    pub base_amount: Option<Amount>,
    /// Sorted strictly by dimension id.
    pub dimension_set: Vec<(u32, VId)>,
    pub memo: Option<Erasable<String>>,
    pub settles: Vec<Settlement>,
}

impl LegPayload {
    #[must_use]
    pub fn simple(side: Side, account_ref: VId, amount: Amount) -> Self {
        Self {
            side,
            account_ref,
            amount,
            base_amount: None,
            dimension_set: Vec::new(),
            memo: None,
            settles: Vec::new(),
        }
    }

    fn encode(&self, w: &mut Writer, sink: &mut Sink<'_>) {
        w.u8(match self.side {
            Side::Debit => 0,
            Side::Credit => 1,
        })
        .u128(self.account_ref.0);
        encode_amount(w, &self.amount);
        w.opt(self.base_amount.as_ref(), encode_amount)
            .list(&self.dimension_set, |w, (d, v)| {
                w.u32(*d).u128(v.0);
            });
        match &self.memo {
            None => {
                w.u8(0);
            }
            Some(m) => {
                w.u8(1);
                sink.erasable(w, m, MAX_MEMO_BYTES);
            }
        }
        w.list(&self.settles, |w, s| {
            s.target.encode(w);
            w.u16(s.ordinal);
            encode_amount(w, &s.amount);
        });
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let side = match r.u8("leg.side")? {
            0 => Side::Debit,
            1 => Side::Credit,
            t => return Err(r.bad_tag("leg.side", t)),
        };
        let account_ref = VId(r.u128("leg.account_ref")?);
        let amount = decode_amount(r)?;
        let base_amount = r.opt("leg.base_amount", decode_amount)?;
        let dimension_set = r.list(MAX_DIMENSIONS_PER_LEG, "leg.dimension_set", |r| {
            Ok((r.u32("dimension.id")?, VId(r.u128("dimension.value")?)))
        })?;
        if !strictly_ascending(&dimension_set, |(d, _)| *d) {
            return Err(r.unsorted("leg.dimension_set"));
        }
        let memo = r.opt("leg.memo", |r| Erasable::decode(r, MAX_MEMO_BYTES))?;
        let settles = r.list(MAX_SETTLES_PER_LEG, "leg.settles", |r| {
            Ok(Settlement {
                target: EntryRef::decode(r)?,
                ordinal: r.u16("settles.ordinal")?,
                amount: decode_amount(r)?,
            })
        })?;
        Ok(Self {
            side,
            account_ref,
            amount,
            base_amount,
            dimension_set,
            memo,
            settles,
        })
    }

    fn validate(&self) -> Result<(), EntryError> {
        // Plan §4.4: a leg moves a positive amount. A negative one is the
        // other side; a zero one moves nothing and is never a journaled fact.
        if self.amount.mantissa <= 0 {
            return Err(invalid(
                "leg.amount",
                "a leg mantissa is positive: swap the side instead of a negative amount, and drop a zero leg",
            ));
        }
        if self.base_amount.is_some_and(|b| b.mantissa < 0) {
            return Err(invalid(
                "leg.base_amount",
                "a base mantissa is non-negative",
            ));
        }
        if self.dimension_set.len() > MAX_DIMENSIONS_PER_LEG
            || !strictly_ascending(&self.dimension_set, |(d, _)| *d)
        {
            return Err(invalid(
                "leg.dimension_set",
                "must be strictly ascending by dimension id and within max_dimensions_per_leg",
            ));
        }
        if self.settles.len() > MAX_SETTLES_PER_LEG {
            return Err(invalid("leg.settles", "exceeds max_settles_per_leg"));
        }
        if self.settles.iter().any(|s| s.amount.mantissa < 0) {
            return Err(invalid(
                "leg.settles",
                "a settlement amount is non-negative",
            ));
        }
        if self.memo.as_ref().is_some_and(|m| !m.fits(MAX_MEMO_BYTES)) {
            return Err(invalid("leg.memo", "exceeds max_memo_bytes"));
        }
        Ok(())
    }
}

/// Per-unit sums over the legs (redundant, verified).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnitTotal {
    pub unit_id: u32,
    pub debits: i128,
    pub credits: i128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Residual {
    pub leg_ordinal: u16,
    pub amount: Amount,
}

/// Functional-currency totals under the entry's FX law (plan §5.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaseTotals {
    pub unit_id: u32,
    pub debits: i128,
    pub credits: i128,
    pub fx_law_oid: Oid,
    /// Sorted.
    pub rate_doc_oids: Vec<Oid>,
    pub residual: Option<Residual>,
}

/// Where the entry came from. The dry-run plan certificate is *not* here: it
/// is computed over `proposal_digest` and therefore binds in the envelope.
// The Migration variant carries three sealed fields; payloads are decoded
// once and held by value, so the size difference is not worth a Box.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EntryOrigin {
    Intent {
        intent_oid: Oid,
        intent_kind: u16,
    },
    Rule {
        rule_version_oid: Oid,
        event_ref: VId,
        inputs_digest: [u8; 32],
    },
    Migration {
        run_ref: VId,
        source_system: String,
        source_id: Erasable<String>,
        source_recorded_at_ns: Option<i64>,
        source_entered_by: Option<Erasable<String>>,
        source_approved_by: Option<Erasable<String>>,
        batch_oid: Oid,
    },
    Control {
        control_kind: ControlKind,
        spec_body_digest: [u8; 32],
    },
    Sweep {
        sweep_kind: u8,
        tick_evidence_oid: Oid,
    },
    /// A scheduled effect (plan §7.6): the schedule it executes and what
    /// triggered it. Tag 5, additive: authorship travels through the
    /// schedule's lineage, never through the minted entry's principal.
    Schedule {
        schedule_ref: VId,
        trigger: ScheduleTrigger,
    },
}

/// What triggered a scheduled effect (plan §7.6 rules (a) and (b)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScheduleTrigger {
    /// The first sweep tick whose civil date reached the scheduled date.
    Sweep { tick_ref: VId },
    /// The `Open` transition of the scheduled date's period.
    OpenPeriod { transition_ref: VId },
}

impl EntryOrigin {
    fn encode(&self, w: &mut Writer, sink: &mut Sink<'_>) {
        match self {
            Self::Intent {
                intent_oid,
                intent_kind,
            } => {
                w.u8(0);
                encode_oid(w, intent_oid);
                w.u16(*intent_kind);
            }
            Self::Rule {
                rule_version_oid,
                event_ref,
                inputs_digest,
            } => {
                w.u8(1);
                encode_oid(w, rule_version_oid);
                w.u128(event_ref.0).fixed(inputs_digest);
            }
            Self::Migration {
                run_ref,
                source_system,
                source_id,
                source_recorded_at_ns,
                source_entered_by,
                source_approved_by,
                batch_oid,
            } => {
                w.u8(2).u128(run_ref.0).str(source_system);
                sink.erasable(w, source_id, MAX_EXTERNAL_ID_BYTES);
                w.opt(source_recorded_at_ns.as_ref(), |w, v| {
                    w.i64(*v);
                });
                for field in [source_entered_by, source_approved_by] {
                    match field {
                        None => {
                            w.u8(0);
                        }
                        Some(e) => {
                            w.u8(1);
                            sink.erasable(w, e, MAX_EXTERNAL_ID_BYTES);
                        }
                    }
                }
                encode_oid(w, batch_oid);
            }
            Self::Control {
                control_kind,
                spec_body_digest,
            } => {
                w.u8(3).u16(control_kind.id()).fixed(spec_body_digest);
            }
            Self::Sweep {
                sweep_kind,
                tick_evidence_oid,
            } => {
                w.u8(4).u8(*sweep_kind);
                encode_oid(w, tick_evidence_oid);
            }
            Self::Schedule {
                schedule_ref,
                trigger,
            } => {
                w.u8(5).u128(schedule_ref.0);
                match trigger {
                    ScheduleTrigger::Sweep { tick_ref } => {
                        w.u8(0).u128(tick_ref.0);
                    }
                    ScheduleTrigger::OpenPeriod { transition_ref } => {
                        w.u8(1).u128(transition_ref.0);
                    }
                }
            }
        }
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(match r.u8("origin.tag")? {
            0 => Self::Intent {
                intent_oid: decode_oid(r, "origin.intent_oid")?,
                intent_kind: r.u16("origin.intent_kind")?,
            },
            1 => Self::Rule {
                rule_version_oid: decode_oid(r, "origin.rule_version_oid")?,
                event_ref: VId(r.u128("origin.event_ref")?),
                inputs_digest: r.fixed("origin.inputs_digest")?,
            },
            2 => Self::Migration {
                run_ref: VId(r.u128("origin.run_ref")?),
                source_system: r.str(MAX_SYSTEM_BYTES, "origin.source_system")?.to_string(),
                source_id: Erasable::decode(r, MAX_EXTERNAL_ID_BYTES)?,
                source_recorded_at_ns: r.opt("origin.source_recorded_at", |r| {
                    r.i64("origin.source_recorded_at")
                })?,
                source_entered_by: r.opt("origin.source_entered_by", |r| {
                    Erasable::decode(r, MAX_EXTERNAL_ID_BYTES)
                })?,
                source_approved_by: r.opt("origin.source_approved_by", |r| {
                    Erasable::decode(r, MAX_EXTERNAL_ID_BYTES)
                })?,
                batch_oid: decode_oid(r, "origin.batch_oid")?,
            },
            3 => Self::Control {
                control_kind: {
                    let id = r.u16("origin.control_kind")?;
                    ControlKind::from_id(id).ok_or_else(|| r.invalid("origin.control_kind"))?
                },
                spec_body_digest: r.fixed("origin.spec_body_digest")?,
            },
            4 => Self::Sweep {
                sweep_kind: r.u8("origin.sweep_kind")?,
                tick_evidence_oid: decode_oid(r, "origin.tick_evidence_oid")?,
            },
            5 => Self::Schedule {
                schedule_ref: VId(r.u128("origin.schedule_ref")?),
                trigger: match r.u8("origin.trigger")? {
                    0 => ScheduleTrigger::Sweep {
                        tick_ref: VId(r.u128("origin.tick_ref")?),
                    },
                    1 => ScheduleTrigger::OpenPeriod {
                        transition_ref: VId(r.u128("origin.transition_ref")?),
                    },
                    t => return Err(r.bad_tag("origin.trigger", t)),
                },
            },
            t => return Err(r.bad_tag("origin.tag", t)),
        })
    }
}

/// Where a document entered the book (plan §9.3 `ImportReceipt.source`).
/// The kinds and connectors a book accepts are `registries/intake_sources.toml`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum IntakeSource {
    /// A principal uploaded the bytes.
    Upload { principal: VId },
    /// A registered connector fetched them.
    Connector { name: String, version: String },
    /// They arrived by e-mail.
    Email { message_id: String },
    /// A registered scanning device captured them.
    Scan { device: String },
}

impl IntakeSource {
    /// The registered kind name (`intake_sources.toml [[kind]]`).
    #[must_use]
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::Upload { .. } => "Upload",
            Self::Connector { .. } => "Connector",
            Self::Email { .. } => "Email",
            Self::Scan { .. } => "Scan",
        }
    }

    /// Every text field is 1..=`max_intake_text_bytes` bytes.
    #[must_use]
    pub fn within_bounds(&self) -> bool {
        let ok = |s: &str| !s.is_empty() && s.len() <= MAX_INTAKE_TEXT_BYTES;
        match self {
            Self::Upload { .. } => true,
            Self::Connector { name, version } => ok(name) && ok(version),
            Self::Email { message_id } => ok(message_id),
            Self::Scan { device } => ok(device),
        }
    }

    pub fn encode(&self, w: &mut Writer) {
        match self {
            Self::Upload { principal } => {
                w.u8(1).u128(principal.0);
            }
            Self::Connector { name, version } => {
                w.u8(2).str(name).str(version);
            }
            Self::Email { message_id } => {
                w.u8(3).str(message_id);
            }
            Self::Scan { device } => {
                w.u8(4).str(device);
            }
        }
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let text = |r: &mut Reader<'_>, what| -> Result<String, DecodeError> {
            Ok(r.str(MAX_INTAKE_TEXT_BYTES, what)?.to_string())
        };
        Ok(match r.u8("intake.tag")? {
            1 => Self::Upload {
                principal: VId(r.u128("intake.principal")?),
            },
            2 => Self::Connector {
                name: text(r, "intake.name")?,
                version: text(r, "intake.version")?,
            },
            3 => Self::Email {
                message_id: text(r, "intake.message_id")?,
            },
            4 => Self::Scan {
                device: text(r, "intake.device")?,
            },
            t => return Err(r.bad_tag("intake.tag", t)),
        })
    }
}

/// Control records carry no legs; the payload says what changed (Appendix A).
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlPayload {
    PeriodTransition {
        period_ref: PeriodRef,
        from: u8,
        to: u8,
        reason_code: u16,
        case_ref: Option<VId>,
    },
    SchemaChange {
        kind: u16,
        canonical_bytes: Vec<u8>,
    },
    PolicyActivation {
        policy_oid: Oid,
        effective_from: DateDay,
        effective_to: DateDay,
    },
    LifecycleTransition {
        object_ref: VId,
        from: u8,
        to: u8,
        proof_refs: Vec<TypedRef>,
        reason_code: u16,
    },
    TimeTick {
        observed_utc_ns: u64,
        source: u8,
        monotonic_ok: bool,
    },
    SweepCursor {
        sweep_kind: u8,
        last_pending_vid: VId,
        tick_ref: VId,
    },
    ScheduleCancelled {
        schedule_ref: VId,
        cause_ref: VId,
    },
    CapabilityEvent {
        commitment: [u8; 32],
        kind: u8,
        caveats_digest: [u8; 32],
    },
    HoldEvent {
        scope_digest: [u8; 32],
        authority_oid: Oid,
        kind: u8,
    },
    ErasureCut {
        subject_ref: VId,
        field_digests: Vec<[u8; 32]>,
    },
    MigrationControl {
        run_ref: VId,
        kind: u8,
        tie_out_digest: [u8; 32],
    },
    /// The control payload of a `Resolution(Voids | Expires)`: the release of
    /// a Pending's reservations. Target and disposition ride in `pending`
    /// (plan §5.4). Tag 11; never valid on a control class.
    ReservationRelease,
    /// An import run's receipt (plan §9.3; class `ImportControl`, tag 13):
    /// what came in, from where, how much, and the Merkle root over the
    /// run's distinct document oids. `receipt_hash` is what the external
    /// party keeps.
    ImportRun {
        source: IntakeSource,
        document_count: u32,
        byte_count: u64,
        oids_root: [u8; 32],
        receipt_hash: [u8; 32],
    },
}

impl ControlPayload {
    fn encode(&self, w: &mut Writer) {
        match self {
            Self::PeriodTransition {
                period_ref,
                from,
                to,
                reason_code,
                case_ref,
            } => {
                w.u8(0);
                period_ref.encode(w);
                w.u8(*from)
                    .u8(*to)
                    .u16(*reason_code)
                    .opt(case_ref.as_ref(), |w, v| {
                        w.u128(v.0);
                    });
            }
            Self::SchemaChange {
                kind,
                canonical_bytes,
            } => {
                w.u8(1).u16(*kind).bytes(canonical_bytes);
            }
            Self::PolicyActivation {
                policy_oid,
                effective_from,
                effective_to,
            } => {
                w.u8(2);
                encode_oid(w, policy_oid);
                encode_day(w, effective_from);
                encode_day(w, effective_to);
            }
            Self::LifecycleTransition {
                object_ref,
                from,
                to,
                proof_refs,
                reason_code,
            } => {
                w.u8(3)
                    .u128(object_ref.0)
                    .u8(*from)
                    .u8(*to)
                    .list(proof_refs, |w, p| p.encode(w))
                    .u16(*reason_code);
            }
            Self::TimeTick {
                observed_utc_ns,
                source,
                monotonic_ok,
            } => {
                w.u8(4)
                    .u64(*observed_utc_ns)
                    .u8(*source)
                    .bool(*monotonic_ok);
            }
            Self::SweepCursor {
                sweep_kind,
                last_pending_vid,
                tick_ref,
            } => {
                w.u8(5)
                    .u8(*sweep_kind)
                    .u128(last_pending_vid.0)
                    .u128(tick_ref.0);
            }
            Self::ScheduleCancelled {
                schedule_ref,
                cause_ref,
            } => {
                w.u8(6).u128(schedule_ref.0).u128(cause_ref.0);
            }
            Self::CapabilityEvent {
                commitment,
                kind,
                caveats_digest,
            } => {
                w.u8(7).fixed(commitment).u8(*kind).fixed(caveats_digest);
            }
            Self::HoldEvent {
                scope_digest,
                authority_oid,
                kind,
            } => {
                w.u8(8).fixed(scope_digest);
                encode_oid(w, authority_oid);
                w.u8(*kind);
            }
            Self::ErasureCut {
                subject_ref,
                field_digests,
            } => {
                w.u8(9).u128(subject_ref.0).list(field_digests, |w, d| {
                    w.fixed(d);
                });
            }
            Self::MigrationControl {
                run_ref,
                kind,
                tie_out_digest,
            } => {
                w.u8(10).u128(run_ref.0).u8(*kind).fixed(tie_out_digest);
            }
            Self::ReservationRelease => {
                w.u8(11);
            }
            Self::ImportRun {
                source,
                document_count,
                byte_count,
                oids_root,
                receipt_hash,
            } => {
                w.u8(13);
                source.encode(w);
                w.u32(*document_count)
                    .u64(*byte_count)
                    .fixed(oids_root)
                    .fixed(receipt_hash);
            }
        }
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(match r.u8("control.tag")? {
            0 => Self::PeriodTransition {
                period_ref: PeriodRef::decode(r)?,
                from: r.u8("control.from")?,
                to: r.u8("control.to")?,
                reason_code: r.u16("control.reason_code")?,
                case_ref: r.opt("control.case_ref", |r| r.u128("control.case_ref").map(VId))?,
            },
            1 => Self::SchemaChange {
                kind: r.u16("control.kind")?,
                canonical_bytes: r
                    .bytes(MAX_SCHEMA_CHANGE_BYTES, "control.canonical_bytes")?
                    .to_vec(),
            },
            2 => Self::PolicyActivation {
                policy_oid: decode_oid(r, "control.policy_oid")?,
                effective_from: decode_day(r, "control.effective_from")?,
                effective_to: decode_day(r, "control.effective_to")?,
            },
            3 => Self::LifecycleTransition {
                object_ref: VId(r.u128("control.object_ref")?),
                from: r.u8("control.from")?,
                to: r.u8("control.to")?,
                proof_refs: r.list(MAX_PROOF_REFS, "control.proof_refs", TypedRef::decode)?,
                reason_code: r.u16("control.reason_code")?,
            },
            4 => Self::TimeTick {
                observed_utc_ns: r.u64("control.observed_utc_ns")?,
                source: r.u8("control.source")?,
                monotonic_ok: r.bool("control.monotonic_ok")?,
            },
            5 => Self::SweepCursor {
                sweep_kind: r.u8("control.sweep_kind")?,
                last_pending_vid: VId(r.u128("control.last_pending_vid")?),
                tick_ref: VId(r.u128("control.tick_ref")?),
            },
            6 => Self::ScheduleCancelled {
                schedule_ref: VId(r.u128("control.schedule_ref")?),
                cause_ref: VId(r.u128("control.cause_ref")?),
            },
            7 => Self::CapabilityEvent {
                commitment: r.fixed("control.commitment")?,
                kind: r.u8("control.kind")?,
                caveats_digest: r.fixed("control.caveats_digest")?,
            },
            8 => Self::HoldEvent {
                scope_digest: r.fixed("control.scope_digest")?,
                authority_oid: decode_oid(r, "control.authority_oid")?,
                kind: r.u8("control.kind")?,
            },
            9 => {
                let subject_ref = VId(r.u128("control.subject_ref")?);
                let field_digests = r.list(MAX_FIELD_DIGESTS, "control.field_digests", |r| {
                    r.fixed("control.field_digest")
                })?;
                if !strictly_ascending(&field_digests, |d| *d) {
                    return Err(r.unsorted("control.field_digests"));
                }
                Self::ErasureCut {
                    subject_ref,
                    field_digests,
                }
            }
            10 => Self::MigrationControl {
                run_ref: VId(r.u128("control.run_ref")?),
                kind: r.u8("control.kind")?,
                tie_out_digest: r.fixed("control.tie_out_digest")?,
            },
            11 => Self::ReservationRelease,
            13 => Self::ImportRun {
                source: IntakeSource::decode(r)?,
                document_count: r.u32("control.document_count")?,
                byte_count: r.u64("control.byte_count")?,
                oids_root: r.fixed("control.oids_root")?,
                receipt_hash: r.fixed("control.receipt_hash")?,
            },
            t => return Err(r.bad_tag("control.tag", t)),
        })
    }

    fn validate(&self) -> Result<(), EntryError> {
        match self {
            Self::PeriodTransition { period_ref, .. } if !period_ref.within_bounds() => Err(
                invalid("control.period_ref", "exceeds max_period_ref_bytes"),
            ),
            Self::SchemaChange {
                canonical_bytes, ..
            } if canonical_bytes.len() > MAX_SCHEMA_CHANGE_BYTES => Err(invalid(
                "control.canonical_bytes",
                "exceeds max_schema_change_bytes",
            )),
            Self::LifecycleTransition { proof_refs, .. } if proof_refs.len() > MAX_PROOF_REFS => {
                Err(invalid("control.proof_refs", "exceeds max_proof_refs"))
            }
            Self::TimeTick {
                observed_utc_ns,
                source,
                ..
            } if *source > 2 || *observed_utc_ns > MAX_TICK_UTC_NS => Err(invalid(
                "control.time_tick",
                "source must be 0..=2 and observed_utc_ns within max_tick_utc_ns",
            )),
            Self::ImportRun {
                source,
                document_count,
                ..
            } if !source.within_bounds() || *document_count == 0 => Err(invalid(
                "control.import_run",
                "an import run names a bounded source and at least one document",
            )),
            Self::ErasureCut { field_digests, .. }
                if field_digests.len() > MAX_FIELD_DIGESTS
                    || !strictly_ascending(field_digests, |d| *d) =>
            {
                Err(invalid(
                    "control.field_digests",
                    "must be strictly ascending and within max_field_digests",
                ))
            }
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// The posted sub-vector is `Entry.legs`; `source_ordinals` is parallel to
    /// it and names, strictly ascending, the original pending leg each posted
    /// leg draws down (plan §5.4).
    Posts {
        source_ordinals: Vec<u16>,
    },
    Voids,
    Expires {
        at_tick: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pending {
    pub timeout_ns: Option<u64>,
    pub resolution_of: Option<EntryRef>,
    pub disposition: Option<Disposition>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SupersessionKind {
    Reverses = 1,
    Replaces = 2,
    Reclassifies = 3,
    Revises = 4,
    Restates = 5,
    Resolves = 6,
}

impl SupersessionKind {
    #[must_use]
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::Reverses,
            2 => Self::Replaces,
            3 => Self::Reclassifies,
            4 => Self::Revises,
            5 => Self::Restates,
            6 => Self::Resolves,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Supersession {
    pub target: EntryRef,
    pub kind: SupersessionKind,
    pub reason_code: u16,
}

/// A provenance-closure head: a document with its public commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct EvidenceRef {
    pub document_oid: Oid,
    pub doc_commit: [u8; 32],
    pub role: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalId {
    pub system: String,
    pub id: Erasable<String>,
}

/// The storable scalar subset a tag may hold, under FrankenAccounting's own
/// codec so the durable format never tracks the substrate's scalar encoding.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TagValue {
    Null,
    Bool(bool),
    Int(i64),
    Text(String),
    Bytes(Vec<u8>),
}

impl Canonical for TagValue {
    fn write_canonical(&self, w: &mut Writer) {
        match self {
            Self::Null => {
                w.u8(0);
            }
            Self::Bool(b) => {
                w.u8(1).bool(*b);
            }
            Self::Int(i) => {
                w.u8(2).i64(*i);
            }
            Self::Text(s) => {
                w.u8(3).str(s);
            }
            Self::Bytes(b) => {
                w.u8(4).bytes(b);
            }
        }
    }

    fn read_canonical(r: &mut Reader<'_>, max: usize) -> Result<Self, DecodeError> {
        Ok(match r.u8("tag.kind")? {
            0 => Self::Null,
            1 => Self::Bool(r.bool("tag.bool")?),
            2 => Self::Int(r.i64("tag.int")?),
            3 => Self::Text(r.str(max.min(MAX_TAG_TEXT_BYTES), "tag.text")?.to_string()),
            4 => Self::Bytes(r.bytes(max.min(MAX_TAG_BYTES_VALUE), "tag.bytes")?.to_vec()),
            t => return Err(r.bad_tag("tag.kind", t)),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tag {
    pub key: String,
    pub value: Erasable<TagValue>,
}

// ---------------------------------------------------------------------------
// The proposal
// ---------------------------------------------------------------------------

/// Every entry field except the envelope (`plan_certificate_oid`,
/// `approvals`) and the two digests: what an approval binds (plan §4.6
/// `EntryProposal`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryPayload {
    pub schema_minor: u16,
    pub book_id: Id128,
    pub branch_id: Id128,
    pub class: EntryClass,
    pub effective_date: DateDay,
    pub document_date: Option<DateDay>,
    pub description: Erasable<String>,
    pub effective_period: Option<PeriodRef>,
    pub legs: Vec<LegPayload>,
    pub control: Option<ControlPayload>,
    /// Sorted by `unit_id`; equal to [`EntryPayload::fold_unit_totals`].
    pub unit_totals: Vec<UnitTotal>,
    pub base_totals: Option<BaseTotals>,
    pub idempotency_key: Vec<u8>,
    pub origin: EntryOrigin,
    pub principal_ref: VId,
    pub session_ref: Option<VId>,
    /// Sorted strictly by `(document_oid, doc_commit, role)`.
    pub evidence: Vec<EvidenceRef>,
    pub supersession: Vec<Supersession>,
    pub pending: Option<Pending>,
    /// Sorted strictly by `(system, id.field_digest)`.
    pub external_ids: Vec<ExternalId>,
    /// Sorted strictly by `key`.
    pub tags: Vec<Tag>,
    /// Additive-minor extensions: `(tag, bytes)` strictly ascending by tag.
    /// A reader at this crate's minor admits only registered tags
    /// (`KNOWN_EXTENSION_TAGS`); a payload written at a higher minor may carry
    /// tags this reader does not know, which it preserves byte-for-byte (the
    /// digests cover them) and skips in meaning. Fields land here first and
    /// move into the positional layout only at a major bump.
    pub extensions: Vec<(u16, Vec<u8>)>,
}

impl EntryPayload {
    /// The per-unit debit and credit sums over `legs`, sorted by unit, with
    /// checked arithmetic.
    pub fn fold_unit_totals(legs: &[LegPayload]) -> Result<Vec<UnitTotal>, EntryError> {
        let mut totals: Vec<UnitTotal> = Vec::new();
        for leg in legs {
            let idx = match totals.binary_search_by_key(&leg.amount.unit.0, |t| t.unit_id) {
                Ok(i) => i,
                Err(i) => {
                    totals.insert(
                        i,
                        UnitTotal {
                            unit_id: leg.amount.unit.0,
                            debits: 0,
                            credits: 0,
                        },
                    );
                    i
                }
            };
            let t = &mut totals[idx];
            let slot = match leg.side {
                Side::Debit => &mut t.debits,
                Side::Credit => &mut t.credits,
            };
            *slot = slot
                .checked_add(leg.amount.mantissa)
                .ok_or(EntryError::Overflow)?;
        }
        Ok(totals)
    }

    /// [`Self::validate`] for a payload this build is about to write: it also
    /// refuses a `schema_minor` above [`SCHEMA_MINOR`] (fa-hoi5). Reading
    /// still accepts a newer writer's minor and preserves its unknown
    /// extensions (the additive-minor law); writing one would journal
    /// extensions this build never validated.
    pub fn validate_for_write(&self) -> Result<(), EntryError> {
        self.validate()?;
        self.check_writer_minor()
    }

    fn check_writer_minor(&self) -> Result<(), EntryError> {
        if self.schema_minor > SCHEMA_MINOR {
            return Err(invalid(
                "schema_minor",
                "a writer seals only the schema minors it knows; register a new extension instead of claiming a newer minor",
            ));
        }
        Ok(())
    }

    /// Structural validation (not the accounting laws).
    pub fn validate(&self) -> Result<(), EntryError> {
        if !self.class.is_registered() {
            return Err(invalid("class", "not a registered entry class"));
        }
        if self.class.is_control() {
            if !self.legs.is_empty() {
                return Err(invalid("legs", "a control class carries no legs"));
            }
            match &self.control {
                None => {
                    return Err(invalid(
                        "control",
                        "a control class carries a control payload",
                    ));
                }
                Some(ControlPayload::ReservationRelease) => {
                    return Err(invalid(
                        "control",
                        "ReservationRelease rides only a Resolution",
                    ));
                }
                Some(c) => c.validate()?,
            }
            if self.pending.is_some() {
                return Err(invalid(
                    "pending",
                    "a control class carries no pending block",
                ));
            }
        } else if self.class == EntryClass::RESOLUTION {
            // Disposition-sensitive arity (plan §5.4).
            let Some(Pending {
                timeout_ns: None,
                resolution_of: Some(_),
                disposition: Some(disposition),
            }) = &self.pending
            else {
                return Err(invalid(
                    "pending",
                    "a Resolution names resolution_of and a disposition, and carries no timeout",
                ));
            };
            match disposition {
                Disposition::Posts { source_ordinals } => {
                    if self.control.is_some() {
                        return Err(invalid(
                            "control",
                            "Resolution(Posts) carries no control payload",
                        ));
                    }
                    if self.legs.len() < 2 || self.legs.len() > MAX_LEGS_PER_ENTRY {
                        return Err(invalid(
                            "legs",
                            "Resolution(Posts) posts a balanced sub-vector of at least two legs",
                        ));
                    }
                    if source_ordinals.len() != self.legs.len()
                        || !strictly_ascending(source_ordinals, |o| *o)
                    {
                        return Err(invalid(
                            "pending.disposition",
                            "source_ordinals is parallel to legs and strictly ascending",
                        ));
                    }
                }
                Disposition::Voids | Disposition::Expires { .. } => {
                    if !self.legs.is_empty() {
                        return Err(invalid("legs", "Resolution(Voids|Expires) carries no legs"));
                    }
                    if self.control != Some(ControlPayload::ReservationRelease) {
                        return Err(invalid(
                            "control",
                            "Resolution(Voids|Expires) carries control = ReservationRelease",
                        ));
                    }
                }
            }
        } else {
            if self.control.is_some() {
                return Err(invalid(
                    "control",
                    "a posting class carries no control payload",
                ));
            }
            let single_sided_statistical = self.legs.len() == 1
                && matches!(
                    self.class,
                    EntryClass::ORIGINAL
                        | EntryClass::ADJUSTING
                        | EntryClass::REVERSAL
                        | EntryClass::MIGRATION
                )
                && fa_money::UnitRegistry::with_defaults()
                    .get(self.legs[0].amount.unit)
                    .map_or(
                        self.legs[0].amount.unit.0 >= 11,
                        fa_money::Unit::allows_single_sided,
                    );
            if self.legs.len() < 2 && !single_sided_statistical {
                return Err(invalid("legs", "a posting class has at least two legs"));
            }
            if self.legs.len() > MAX_LEGS_PER_ENTRY {
                return Err(invalid("legs", "exceeds max_legs_per_entry"));
            }
            match (&self.pending, self.class == EntryClass::PENDING) {
                (None, false) => {}
                (
                    Some(Pending {
                        resolution_of: None,
                        disposition: None,
                        ..
                    }),
                    true,
                ) => {}
                (Some(_), true) => {
                    return Err(invalid(
                        "pending",
                        "a Pending carries neither resolution_of nor a disposition",
                    ));
                }
                (Some(_), false) => {
                    return Err(invalid(
                        "pending",
                        "only Pending and Resolution carry a pending block",
                    ));
                }
                (None, true) => {
                    return Err(invalid("pending", "a Pending carries a pending block"));
                }
            }
        }
        if self.extensions.len() > MAX_EXTENSIONS
            || self
                .extensions
                .iter()
                .any(|(_, b)| b.len() > MAX_EXTENSION_BYTES)
            || !strictly_ascending(&self.extensions, |(t, _)| *t)
        {
            return Err(invalid(
                "extensions",
                "must be strictly ascending by tag and within max_extensions / max_extension_bytes",
            ));
        }
        if self.schema_minor < EXTENSIONS_MINOR && !self.extensions.is_empty() {
            return Err(invalid(
                "extensions",
                "a minor-0 payload has no extension block; write schema_minor >= 1",
            ));
        }
        if self.schema_minor <= SCHEMA_MINOR
            && self
                .extensions
                .iter()
                .any(|(t, _)| !KNOWN_EXTENSION_TAGS.contains(t))
        {
            return Err(invalid(
                "extensions",
                "an unregistered extension tag at this schema minor",
            ));
        }
        if self
            .extensions
            .iter()
            .any(|(t, b)| *t == EVENT_REF_EXTENSION && b.len() != 48)
        {
            return Err(invalid(
                "extensions.event_ref",
                "fa:event-ref:v1 requires 48 bytes (event_vid u128 LE || event_digest [u8; 32])",
            ));
        }
        if let Some((_, bytes)) = self
            .extensions
            .iter()
            .find(|(t, _)| *t == OBLIGATION_MATURITY_EXTENSION)
        {
            crate::obligation::validate_terms(bytes, &self.legs)
                .map_err(|(what, why)| invalid(what, why))?;
        }
        if let Some((_, bytes)) = self
            .extensions
            .iter()
            .find(|(t, _)| *t == VALUATION_ADJUSTMENT_EXTENSION)
        {
            crate::valuation::validate_terms(bytes).map_err(|(what, why)| invalid(what, why))?;
        }
        if let Some((_, bytes)) = self
            .extensions
            .iter()
            .find(|(t, _)| *t == PROPORTIONAL_POST_EXTENSION)
        {
            if self.schema_minor < PROPORTIONAL_POST_SCHEMA_MINOR
                || self.class != EntryClass::RESOLUTION
                || !matches!(
                    self.pending.as_ref().and_then(|p| p.disposition.as_ref()),
                    Some(Disposition::Posts { .. })
                )
            {
                return Err(invalid(
                    "extensions.proportional_post",
                    "a proportional-post basis belongs only to Resolution(Posts) at schema minor 2 or later",
                ));
            }
            crate::proportional::ProportionalPostBasis::decode(bytes).map_err(|_| {
                invalid(
                    "extensions.proportional_post",
                    "unknown law/version or malformed bounded exact-rate basis",
                )
            })?;
        }
        if let Some((_, bytes)) = self
            .extensions
            .iter()
            .find(|(t, _)| *t == PRIOR_PERIOD_ADJUSTMENT_EXTENSION)
        {
            if self.schema_minor < PRIOR_PERIOD_ADJUSTMENT_SCHEMA_MINOR
                || !matches!(
                    self.class,
                    EntryClass::ORIGINAL
                        | EntryClass::ADJUSTING
                        | EntryClass::PRIOR_PERIOD_ADJUSTMENT
                )
            {
                return Err(invalid(
                    "extensions.prior_period_adjustment",
                    "a prior-period-adjustment basis belongs to a case posting or its Original/Adjusting rehearsal at schema minor 3 or later",
                ));
            }
            PriorPeriodAdjustment::decode(bytes).map_err(|_| {
                invalid(
                    "extensions.prior_period_adjustment",
                    "unknown version or malformed bounded historical PeriodRef",
                )
            })?;
        }
        if let (Some((_, bytes)), EntryOrigin::Rule { event_ref, .. }) = (
            self.extensions
                .iter()
                .find(|(t, _)| *t == EVENT_REF_EXTENSION),
            &self.origin,
        ) {
            let mut vid_bytes = [0u8; 16];
            vid_bytes.copy_from_slice(&bytes[..16]);
            if VId(u128::from_le_bytes(vid_bytes)) != *event_ref {
                return Err(invalid(
                    "extensions.event_ref",
                    "must match EntryOrigin::Rule event_ref when both are present",
                ));
            }
        }
        if let Some((_, bytes)) = self
            .extensions
            .iter()
            .find(|(tag, _)| *tag == YEAR_END_CLOSE_EXTENSION)
            && (self.class != EntryClass::CLOSING
                || !matches!(&self.origin, EntryOrigin::Intent { intent_kind: 1, .. })
                || crate::closing::YearEndCloseBasis::decode(bytes).is_err())
        {
            return Err(invalid(
                "extensions.year_end_close",
                "requires a canonical intrinsic YearEndClose basis on a Closing PostEntry intent",
            ));
        }
        if let Some((_, bytes)) = self
            .extensions
            .iter()
            .find(|(tag, _)| *tag == FX_REVALUATION_EXTENSION)
            && (self.class != EntryClass::REVALUATION
                || !matches!(&self.origin, EntryOrigin::Intent { intent_kind: 1, .. })
                || crate::revaluation::FxRevaluationBasis::decode(bytes).is_err())
        {
            return Err(invalid(
                "extensions.fx_revaluation",
                "requires a canonical source-bound FX revaluation basis on a Revaluation PostEntry intent",
            ));
        }
        for leg in &self.legs {
            leg.validate()?;
        }
        if self.unit_totals != Self::fold_unit_totals(&self.legs)? {
            return Err(EntryError::TotalsMismatch);
        }
        if self.idempotency_key.is_empty() || self.idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES
        {
            return Err(invalid(
                "idempotency_key",
                "1..=max_idempotency_key_bytes bytes",
            ));
        }
        if self
            .effective_period
            .as_ref()
            .is_some_and(|p| !p.within_bounds())
        {
            return Err(invalid("effective_period", "exceeds max_period_ref_bytes"));
        }
        // Sealed fields are bounded by the plaintext limits the decoder
        // enforces; a field that cannot be read back is never encoded.
        if !self.description.fits(MAX_DESCRIPTION_BYTES) {
            return Err(invalid("description", "exceeds max_description_bytes"));
        }
        if self
            .external_ids
            .iter()
            .any(|e| !e.id.fits(MAX_EXTERNAL_ID_BYTES))
        {
            return Err(invalid("external_ids.id", "exceeds max_external_id_bytes"));
        }
        if self
            .tags
            .iter()
            .any(|t| !t.value.fits(MAX_TAG_BYTES_VALUE + 1))
        {
            return Err(invalid("tags.value", "exceeds max_tag_bytes_value"));
        }
        if let EntryOrigin::Migration {
            source_id,
            source_entered_by,
            source_approved_by,
            ..
        } = &self.origin
            && (!source_id.fits(MAX_EXTERNAL_ID_BYTES)
                || [source_entered_by, source_approved_by]
                    .into_iter()
                    .flatten()
                    .any(|e| !e.fits(MAX_EXTERNAL_ID_BYTES)))
        {
            return Err(invalid(
                "origin.migration",
                "a migrated source field exceeds max_external_id_bytes",
            ));
        }
        if let Some(b) = &self.base_totals {
            if b.rate_doc_oids.len() > MAX_RATE_DOCS
                || !strictly_ascending(&b.rate_doc_oids, |o| *o)
            {
                return Err(invalid(
                    "base_totals.rate_doc_oids",
                    "must be strictly ascending and within max_rate_docs",
                ));
            }
            if b.residual
                .is_some_and(|r| usize::from(r.leg_ordinal) >= self.legs.len())
            {
                return Err(invalid(
                    "base_totals.residual",
                    "leg_ordinal names a leg that does not exist",
                ));
            }
        }
        if self.evidence.len() > MAX_EVIDENCE_PER_ENTRY
            || !strictly_ascending(&self.evidence, |e| *e)
        {
            return Err(invalid(
                "evidence",
                "must be strictly ascending and within max_evidence_per_entry",
            ));
        }
        if self.supersession.len() > MAX_SUPERSESSION_PER_ENTRY {
            return Err(invalid(
                "supersession",
                "exceeds max_supersession_per_entry",
            ));
        }
        if self.external_ids.len() > MAX_EXTERNAL_IDS
            || self
                .external_ids
                .iter()
                .any(|x| x.system.len() > MAX_SYSTEM_BYTES)
            || !strictly_ascending(&self.external_ids, |x| {
                (x.system.clone(), x.id.field_digest())
            })
        {
            return Err(invalid(
                "external_ids",
                "must be strictly ascending by (system, id digest) and within bounds",
            ));
        }
        let tag_bytes: usize = self
            .tags
            .iter()
            .map(|t| t.key.len() + t.value.wire_len())
            .sum();
        if self.tags.len() > MAX_TAGS
            || tag_bytes > MAX_TAGS_BYTES
            || self
                .tags
                .iter()
                .any(|t| t.key.is_empty() || t.key.len() > MAX_TAG_KEY_BYTES)
            || !strictly_ascending(&self.tags, |t| t.key.clone())
        {
            return Err(invalid(
                "tags",
                "must be strictly ascending by key and within max_tags / max_tags_bytes",
            ));
        }
        Ok(())
    }

    fn encode_into(&self, w: &mut Writer, sink: &mut Sink<'_>) {
        w.u16(SCHEMA_MAJOR)
            .u16(self.schema_minor)
            .fixed(&self.book_id.0)
            .fixed(&self.branch_id.0)
            .u16(self.class.0);
        encode_day(w, &self.effective_date);
        w.opt(self.document_date.as_ref(), encode_day);
        sink.erasable(w, &self.description, MAX_DESCRIPTION_BYTES);
        w.opt(self.effective_period.as_ref(), |w, p| p.encode(w));
        w.list(&self.legs, |w, l| l.encode(w, sink));
        w.opt(self.control.as_ref(), |w, c| c.encode(w))
            .list(&self.unit_totals, |w, t| {
                w.u32(t.unit_id).i128(t.debits).i128(t.credits);
            })
            .opt(self.base_totals.as_ref(), |w, b| {
                w.u32(b.unit_id).i128(b.debits).i128(b.credits);
                encode_oid(w, &b.fx_law_oid);
                w.list(&b.rate_doc_oids, encode_oid)
                    .opt(b.residual.as_ref(), |w, r| {
                        w.u16(r.leg_ordinal);
                        encode_amount(w, &r.amount);
                    });
            })
            .bytes(&self.idempotency_key);
        self.origin.encode(w, sink);
        w.u128(self.principal_ref.0)
            .opt(self.session_ref.as_ref(), |w, v| {
                w.u128(v.0);
            })
            .list(&self.evidence, |w, e| {
                encode_oid(w, &e.document_oid);
                w.fixed(&e.doc_commit).u8(e.role);
            })
            .list(&self.supersession, |w, s| {
                s.target.encode(w);
                w.u8(s.kind as u8).u16(s.reason_code);
            });
        match &self.pending {
            None => {
                w.u8(0);
            }
            Some(p) => {
                w.u8(1)
                    .opt(p.timeout_ns.as_ref(), |w, t| {
                        w.u64(*t);
                    })
                    .opt(p.resolution_of.as_ref(), |w, r| r.encode(w));
                match &p.disposition {
                    None => {
                        w.u8(0);
                    }
                    Some(Disposition::Posts { source_ordinals }) => {
                        // Tag 3: the sub-vector representation of plan §5.4.
                        // Tag 0 (`posted_legs`) is retired, never reread.
                        w.u8(1).u8(3);
                        w.list(source_ordinals, |w, o| {
                            w.u16(*o);
                        });
                    }
                    Some(Disposition::Voids) => {
                        w.u8(1).u8(1);
                    }
                    Some(Disposition::Expires { at_tick }) => {
                        w.u8(1).u8(2).u64(*at_tick);
                    }
                }
            }
        }
        w.list(&self.external_ids, |w, x| {
            w.str(&x.system);
            sink.erasable(w, &x.id, MAX_EXTERNAL_ID_BYTES);
        });
        w.list(&self.tags, |w, t| {
            w.str(&t.key);
            sink.erasable(w, &t.value, MAX_TAG_BYTES_VALUE + 1);
        });
        if self.schema_minor >= EXTENSIONS_MINOR {
            w.list(&self.extensions, |w, (tag, bytes)| {
                w.u16(*tag).bytes(bytes);
            });
        }
    }

    fn decode_from(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let major = r.u16("schema_major")?;
        if major != SCHEMA_MAJOR {
            return Err(r.invalid("schema_major"));
        }
        let schema_minor = r.u16("schema_minor")?;
        let book_id = Id128(r.fixed("book_id")?);
        let branch_id = Id128(r.fixed("branch_id")?);
        let class = EntryClass(r.u16("class")?);
        let effective_date = decode_day(r, "effective_date")?;
        let document_date = r.opt("document_date", |r| decode_day(r, "document_date"))?;
        let description = Erasable::decode(r, MAX_DESCRIPTION_BYTES)?;
        let effective_period = r.opt("effective_period", PeriodRef::decode)?;
        let legs = r.list(MAX_LEGS_PER_ENTRY, "legs", LegPayload::decode)?;
        let control = r.opt("control", ControlPayload::decode)?;
        let unit_totals = r.list(MAX_LEGS_PER_ENTRY, "unit_totals", |r| {
            Ok(UnitTotal {
                unit_id: r.u32("unit_totals.unit_id")?,
                debits: r.i128("unit_totals.debits")?,
                credits: r.i128("unit_totals.credits")?,
            })
        })?;
        let base_totals = r.opt("base_totals", |r| {
            Ok(BaseTotals {
                unit_id: r.u32("base_totals.unit_id")?,
                debits: r.i128("base_totals.debits")?,
                credits: r.i128("base_totals.credits")?,
                fx_law_oid: decode_oid(r, "base_totals.fx_law_oid")?,
                rate_doc_oids: r.list(MAX_RATE_DOCS, "base_totals.rate_doc_oids", |r| {
                    decode_oid(r, "base_totals.rate_doc_oid")
                })?,
                residual: r.opt("base_totals.residual", |r| {
                    Ok(Residual {
                        leg_ordinal: r.u16("residual.leg_ordinal")?,
                        amount: decode_amount(r)?,
                    })
                })?,
            })
        })?;
        let idempotency_key = r
            .bytes(MAX_IDEMPOTENCY_KEY_BYTES, "idempotency_key")?
            .to_vec();
        let origin = EntryOrigin::decode(r)?;
        let principal_ref = VId(r.u128("principal_ref")?);
        let session_ref = r.opt("session_ref", |r| r.u128("session_ref").map(VId))?;
        let evidence = r.list(MAX_EVIDENCE_PER_ENTRY, "evidence", |r| {
            Ok(EvidenceRef {
                document_oid: decode_oid(r, "evidence.document_oid")?,
                doc_commit: r.fixed("evidence.doc_commit")?,
                role: r.u8("evidence.role")?,
            })
        })?;
        let supersession = r.list(MAX_SUPERSESSION_PER_ENTRY, "supersession", |r| {
            let target = EntryRef::decode(r)?;
            let k = r.u8("supersession.kind")?;
            let kind =
                SupersessionKind::from_u8(k).ok_or_else(|| r.bad_tag("supersession.kind", k))?;
            Ok(Supersession {
                target,
                kind,
                reason_code: r.u16("supersession.reason_code")?,
            })
        })?;
        let pending = r.opt("pending", |r| {
            Ok(Pending {
                timeout_ns: r.opt("pending.timeout_ns", |r| r.u64("pending.timeout_ns"))?,
                resolution_of: r.opt("pending.resolution_of", EntryRef::decode)?,
                disposition: r.opt("pending.disposition", |r| {
                    Ok(match r.u8("disposition.tag")? {
                        3 => Disposition::Posts {
                            source_ordinals: r.list(
                                MAX_LEGS_PER_ENTRY,
                                "disposition.source_ordinals",
                                |r| r.u16("disposition.source_ordinal"),
                            )?,
                        },
                        // The retired `posted_legs` representation: no kernel
                        // ever admitted it, so it is refused rather than read.
                        0 => {
                            return Err(r.bad_tag(
                                "disposition.tag (retired posted_legs representation)",
                                0,
                            ));
                        }
                        1 => Disposition::Voids,
                        2 => Disposition::Expires {
                            at_tick: r.u64("disposition.at_tick")?,
                        },
                        t => return Err(r.bad_tag("disposition.tag", t)),
                    })
                })?,
            })
        })?;
        let external_ids = r.list(MAX_EXTERNAL_IDS, "external_ids", |r| {
            Ok(ExternalId {
                system: r.str(MAX_SYSTEM_BYTES, "external_ids.system")?.to_string(),
                id: Erasable::decode(r, MAX_EXTERNAL_ID_BYTES)?,
            })
        })?;
        let tags = r.list(MAX_TAGS, "tags", |r| {
            Ok(Tag {
                key: r.str(MAX_TAG_KEY_BYTES, "tags.key")?.to_string(),
                value: Erasable::decode(r, MAX_TAG_BYTES_VALUE + 1)?,
            })
        })?;
        // Minor 0 bytes end at `tags`; the extension block exists from minor 1.
        let extensions = if schema_minor >= EXTENSIONS_MINOR {
            r.list(MAX_EXTENSIONS, "extensions", |r| {
                Ok((
                    r.u16("extension.tag")?,
                    r.bytes(MAX_EXTENSION_BYTES, "extension.bytes")?.to_vec(),
                ))
            })?
        } else {
            Vec::new()
        };
        Ok(Self {
            schema_minor,
            book_id,
            branch_id,
            class,
            effective_date,
            document_date,
            description,
            effective_period,
            legs,
            control,
            unit_totals,
            base_totals,
            idempotency_key,
            origin,
            principal_ref,
            session_ref,
            evidence,
            supersession,
            pending,
            external_ids,
            tags,
            extensions,
        })
    }

    /// The canonical proposal bytes (validated first).
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EntryError> {
        self.validate()?;
        let mut w = Writer::with_capacity(512);
        self.encode_into(&mut w, &mut Sink::Wire);
        Ok(w.finish()?)
    }

    /// `BLAKE3("fa:entry-proposal:v1" ‖ canonical(proposal))`.
    pub fn proposal_digest(&self) -> Result<[u8; 32], EntryError> {
        Ok(proposal_digest_of(&self.canonical_bytes()?))
    }

    /// The private semantic transcript digest: the proposal encoded with
    /// every erasable field opened under `key` and written as plaintext.
    /// Computed in memory for retry decisions only; never persisted or
    /// logged. Fails with [`EntryError::Sealed`] when any field cannot be
    /// opened, in which case equivalence is not claimed.
    pub fn semantic_digest(&self, key: &SealKey) -> Result<[u8; 32], EntryError> {
        self.validate()?;
        let mut w = Writer::with_capacity(512);
        let mut sink = Sink::Plain { key, failed: None };
        self.encode_into(&mut w, &mut sink);
        if let Sink::Plain {
            failed: Some(e), ..
        } = sink
        {
            return Err(EntryError::Sealed(e));
        }
        let bytes = w.finish()?;
        let mut h = Hasher::new();
        h.update(SEMANTIC_DIGEST_DOMAIN);
        h.update(&bytes);
        Ok(h.finalize().0)
    }

    /// Bind the envelope — the dry-run plan certificate (if any) and the
    /// approval transcript — and produce the committed entry. Every new
    /// entry is sealed here, so a schema minor this build does not know is
    /// refused here as well as at admission (fa-hoi5).
    pub fn seal(
        self,
        approvals: Vec<ApprovalRef>,
        plan_certificate: Option<Oid>,
    ) -> Result<Entry, EntryError> {
        self.check_writer_minor()?;
        self.seal_unchecked(approvals, plan_certificate)
    }

    /// [`Self::seal`] without the writer-minor check: how a newer writer's
    /// entry is built for this module's own decode tests.
    fn seal_unchecked(
        self,
        approvals: Vec<ApprovalRef>,
        plan_certificate: Option<Oid>,
    ) -> Result<Entry, EntryError> {
        let proposal_bytes = self.canonical_bytes()?;
        if approvals.len() > MAX_APPROVALS {
            return Err(invalid("approvals", "exceeds max_approvals"));
        }
        let proposal_digest = proposal_digest_of(&proposal_bytes);
        let envelope_bytes = encode_envelope(plan_certificate.as_ref(), &approvals)?;
        let entry_digest = entry_digest_of(&proposal_digest, &envelope_bytes);
        let total = proposal_bytes.len() + envelope_bytes.len() + 64;
        if total > MAX_ENTRY_BYTES {
            return Err(EntryError::TooLarge {
                bytes: total,
                max: MAX_ENTRY_BYTES,
            });
        }
        Ok(Entry {
            proposal: self,
            plan_certificate,
            approvals,
            proposal_digest,
            entry_digest,
        })
    }

    /// Bind a case adjustment or its rehearsal template to its historical
    /// error period. This changes the proposal digest and its approvals.
    pub fn with_prior_period_adjustment(
        &mut self,
        relates_to: &PeriodRef,
    ) -> Result<(), EncodeError> {
        let bytes = PriorPeriodAdjustment {
            relates_to: relates_to.clone(),
        }
        .encode()?;
        self.schema_minor = self.schema_minor.max(PRIOR_PERIOD_ADJUSTMENT_SCHEMA_MINOR);
        match self
            .extensions
            .binary_search_by_key(&PRIOR_PERIOD_ADJUSTMENT_EXTENSION, |(tag, _)| *tag)
        {
            Ok(index) => self.extensions[index].1 = bytes,
            Err(index) => self
                .extensions
                .insert(index, (PRIOR_PERIOD_ADJUSTMENT_EXTENSION, bytes)),
        }
        Ok(())
    }

    /// Read the retained source period without inferring one for legacy
    /// entries that predate the extension.
    pub fn prior_period_adjustment(&self) -> Result<Option<PriorPeriodAdjustment>, DecodeError> {
        self.extensions
            .iter()
            .find(|(tag, _)| *tag == PRIOR_PERIOD_ADJUSTMENT_EXTENSION)
            .map(|(_, bytes)| PriorPeriodAdjustment::decode(bytes))
            .transpose()
    }

    /// Attach or replace the REA `Event` citation (`EVENT_REF_EXTENSION = 6`:
    /// `event_vid: u128 LE ‖ event_digest: [u8; 32]`, 48 bytes).
    pub fn with_event_ref(&mut self, event_vid: VId, event_digest: [u8; 32]) {
        self.schema_minor = self.schema_minor.max(EXTENSIONS_MINOR);
        let mut bytes = Vec::with_capacity(48);
        bytes.extend_from_slice(&event_vid.0.to_le_bytes());
        bytes.extend_from_slice(&event_digest);
        match self
            .extensions
            .binary_search_by_key(&EVENT_REF_EXTENSION, |(t, _)| *t)
        {
            Ok(i) => self.extensions[i].1 = bytes,
            Err(i) => self.extensions.insert(i, (EVENT_REF_EXTENSION, bytes)),
        }
    }

    /// Return the REA `Event` cited by this proposal, if any:
    /// - `(event_vid, Some(event_digest))` when `EVENT_REF_EXTENSION` (tag 6) is present;
    /// - `(event_ref, None)` when `origin` is `EntryOrigin::Rule { event_ref, .. }` and tag 6 is absent.
    #[must_use]
    pub fn cited_event(&self) -> Option<(VId, Option<[u8; 32]>)> {
        if let Some((_, bytes)) = self
            .extensions
            .iter()
            .find(|(t, _)| *t == EVENT_REF_EXTENSION)
            && bytes.len() == 48
        {
            let mut vid_bytes = [0u8; 16];
            vid_bytes.copy_from_slice(&bytes[..16]);
            let mut digest = [0u8; 32];
            digest.copy_from_slice(&bytes[16..48]);
            return Some((VId(u128::from_le_bytes(vid_bytes)), Some(digest)));
        }
        if let EntryOrigin::Rule { event_ref, .. } = &self.origin {
            return Some((*event_ref, None));
        }
        None
    }
}

fn proposal_digest_of(proposal_bytes: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(PROPOSAL_DIGEST_DOMAIN);
    h.update(proposal_bytes);
    h.finalize().0
}

fn entry_digest_of(proposal_digest: &[u8; 32], envelope_bytes: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(ENTRY_DIGEST_DOMAIN);
    h.update(proposal_digest);
    h.update(envelope_bytes);
    h.finalize().0
}

/// `opt(plan_certificate_oid) ‖ list(approvals)`.
fn encode_envelope(
    plan_certificate: Option<&Oid>,
    approvals: &[ApprovalRef],
) -> Result<Vec<u8>, EncodeError> {
    let mut w = Writer::with_capacity(1 + 32 + 4 + approvals.len() * 48);
    w.opt(plan_certificate, encode_oid)
        .list(approvals, |w, a| a.encode(w));
    w.finish()
}

// ---------------------------------------------------------------------------
// The committed envelope
// ---------------------------------------------------------------------------

/// `proposal ‖ opt(plan_certificate_oid) ‖ approvals ‖ proposal_digest ‖ entry_digest`
/// on the wire. Only [`EntryPayload::seal`] and [`Entry::decode`] construct
/// one, so the digests always match the fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub proposal: EntryPayload,
    /// The dry-run certificate this entry was committed under, if any
    /// (Appendix A construction order: it is built over `proposal_digest`).
    pub plan_certificate: Option<Oid>,
    pub approvals: Vec<ApprovalRef>,
    pub proposal_digest: [u8; 32],
    pub entry_digest: [u8; 32],
}

impl Entry {
    /// The `_fa_payload` bytes.
    pub fn encode(&self) -> Result<Vec<u8>, EntryError> {
        let mut bytes = self.proposal.canonical_bytes()?;
        bytes.extend_from_slice(&encode_envelope(
            self.plan_certificate.as_ref(),
            &self.approvals,
        )?);
        bytes.extend_from_slice(&self.proposal_digest);
        bytes.extend_from_slice(&self.entry_digest);
        Ok(bytes)
    }

    /// Decode and verify: structure, both digests, no trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, EntryError> {
        if bytes.len() > MAX_ENTRY_BYTES {
            return Err(EntryError::TooLarge {
                bytes: bytes.len(),
                max: MAX_ENTRY_BYTES,
            });
        }
        let mut r = Reader::new(bytes);
        let proposal = EntryPayload::decode_from(&mut r)?;
        let proposal_end = r.offset();
        let plan_certificate = r.opt("plan_certificate_oid", |r| {
            decode_oid(r, "plan_certificate_oid")
        })?;
        let approvals = r.list(MAX_APPROVALS, "approvals", ApprovalRef::decode)?;
        let envelope_end = r.offset();
        let proposal_digest: [u8; 32] = r.fixed("proposal_digest")?;
        let entry_digest: [u8; 32] = r.fixed("entry_digest")?;
        r.finish()?;
        proposal.validate()?;
        if proposal_digest_of(&bytes[..proposal_end]) != proposal_digest {
            return Err(EntryError::DigestMismatch {
                which: "proposal_digest",
            });
        }
        if entry_digest_of(&proposal_digest, &bytes[proposal_end..envelope_end]) != entry_digest {
            return Err(EntryError::DigestMismatch {
                which: "entry_digest",
            });
        }
        Ok(Self {
            proposal,
            plan_certificate,
            approvals,
            proposal_digest,
            entry_digest,
        })
    }

    #[must_use]
    pub fn entry_ref(&self, vid: VId) -> EntryRef {
        EntryRef {
            vid,
            entry_digest: self.entry_digest,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::erasable::SealKey;

    const KEY: SealKey = SealKey([7; 32]);
    const USD: UnitId = UnitId(1);

    fn desc(s: &str) -> Erasable<String> {
        Erasable::seal(&s.to_string(), None, &KEY, [1; 32], [2; 24])
    }

    fn proposal(legs: Vec<LegPayload>) -> EntryPayload {
        let unit_totals = EntryPayload::fold_unit_totals(&legs).unwrap();
        EntryPayload {
            schema_minor: SCHEMA_MINOR,
            book_id: Id128([9; 16]),
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: DateDay(20_000),
            document_date: Some(DateDay(19_999)),
            description: desc("Office rent, March"),
            effective_period: None,
            legs,
            control: None,
            unit_totals,
            base_totals: None,
            idempotency_key: b"inv-1001".to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([1; 32]),
                intent_kind: 1,
            },
            principal_ref: VId(77),
            session_ref: Some(VId(78)),
            evidence: vec![EvidenceRef {
                document_oid: Oid([3; 32]),
                doc_commit: [4; 32],
                role: 1,
            }],
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: vec![Tag {
                key: "cost_center".into(),
                value: Erasable::seal(&TagValue::Text("HQ".into()), None, &KEY, [5; 32], [6; 24]),
            }],
        }
    }

    fn two_legs() -> Vec<LegPayload> {
        vec![
            LegPayload::simple(Side::Debit, VId(1), Amount::new(USD, 120_000)),
            LegPayload::simple(Side::Credit, VId(2), Amount::new(USD, 120_000)),
        ]
    }

    /// fa-g23: the code's kinds are exactly the registry's rows (ids, names,
    /// classes); the reserved ids have no constant until their class lands.
    #[test]
    fn code_control_kinds_match_registry() {
        let classes = fa_registry::EntryClasses::embedded().unwrap();
        let reg = fa_registry::ControlKinds::embedded(&classes).unwrap();
        assert_eq!(reg.rows.len(), ControlKind::ALL.len());
        for row in &reg.rows {
            let k = ControlKind::from_id(row.id).expect("kind in code");
            assert_eq!(k.name(), row.name, "{}", row.id);
            assert_eq!(
                k.class().and_then(EntryClass::name),
                Some(row.class.as_str()),
                "{}",
                row.name
            );
        }
        for r in &reg.reserved {
            assert_eq!(ControlKind::from_id(r.id), None, "{} is reserved", r.name);
        }
    }

    /// fa-g23: an origin naming an unregistered kind does not decode; a
    /// registered one round-trips as its id.
    #[test]
    fn an_unregistered_control_kind_is_unencodable() {
        let origin = |id: u16| {
            let mut w = Writer::new();
            w.u8(3).u16(id).fixed(&[5; 32]);
            w.finish().unwrap()
        };
        for (kind, name, _) in ControlKind::ALL {
            let bytes = origin(kind.id());
            let back = EntryOrigin::decode(&mut Reader::new(&bytes)).expect(name);
            assert_eq!(
                back,
                EntryOrigin::Control {
                    control_kind: *kind,
                    spec_body_digest: [5; 32]
                }
            );
        }
        // The negative probes stay beyond every registered control kind, so
        // registering the next kind does not turn one into a valid id.
        let beyond = ControlKind::ALL
            .iter()
            .map(|(kind, _, _)| kind.id())
            .max()
            .unwrap()
            + 1;
        for id in [0, beyond, beyond + 1, u16::MAX] {
            assert!(
                EntryOrigin::decode(&mut Reader::new(&origin(id))).is_err(),
                "control_kind {id}"
            );
        }
    }

    /// fa-g23, the kernel's staging cross-check: every registered kind stages
    /// a record of its own class and is refused on every other control class
    /// and on a posting class.
    #[test]
    fn a_control_record_stages_only_under_its_registered_kind() {
        let record = |class: EntryClass, kind: ControlKind, legs: Vec<LegPayload>| {
            let mut p = proposal(legs);
            p.class = class;
            if class.is_control() {
                p.control = Some(ControlPayload::TimeTick {
                    observed_utc_ns: 1,
                    source: 0,
                    monotonic_ok: true,
                });
                p.evidence = Vec::new();
            }
            p.origin = EntryOrigin::Control {
                control_kind: kind,
                spec_body_digest: [5; 32],
            };
            p.seal(vec![], None).unwrap()
        };
        let classes: Vec<EntryClass> = EntryClass::ALL
            .iter()
            .filter(|(_, _, control)| *control)
            .map(|(t, _, _)| EntryClass(*t))
            .collect();
        for (kind, name, own) in ControlKind::ALL {
            assert!(
                crate::mirrors::entry_mirrors(&record(*own, *kind, Vec::new())).is_ok(),
                "{name} stages on its own class"
            );
            for class in classes.iter().filter(|c| *c != own) {
                assert_eq!(
                    crate::mirrors::entry_mirrors(&record(*class, *kind, Vec::new())).unwrap_err(),
                    crate::mirrors::MirrorError::ControlKind {
                        class: class.0,
                        kind: kind.id()
                    },
                    "{name} on {:?}",
                    class.name()
                );
            }
            assert!(
                crate::mirrors::entry_mirrors(&record(EntryClass::ORIGINAL, *kind, two_legs()))
                    .is_err(),
                "{name} on a posting class"
            );
        }
    }

    /// The source gate (fa-g23): outside this file no code names a control
    /// kind by number. The scanner flags a planted line, then the workspace.
    #[test]
    fn no_control_kind_is_named_by_number_outside_the_registry_symbols() {
        fn offending(source: &str) -> Vec<String> {
            source
                .lines()
                .map(str::trim)
                .filter(|l| !l.starts_with("//"))
                .filter(|l| {
                    ["control_kind:", "ControlKind(", "ControlKind::from_id("]
                        .iter()
                        .any(|pat| {
                            l.match_indices(pat).any(|(i, _)| {
                                l[i + pat.len()..]
                                    .trim_start()
                                    .starts_with(|c: char| c.is_ascii_digit())
                            })
                        })
                })
                .map(str::to_string)
                .collect()
        }
        assert_eq!(
            offending("let o = EntryOrigin::Control { control_kind: 4, spec_body_digest };"),
            ["let o = EntryOrigin::Control { control_kind: 4, spec_body_digest };"]
        );
        assert_eq!(offending("x = ControlKind::from_id( 7);").len(), 1);
        assert!(offending("control_kind: ControlKind::TIME_TICK,").is_empty());
        let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mut stack = vec![crates];
        let mut found = Vec::new();
        let mut scanned = 0usize;
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("read crates") {
                let path = entry.expect("dir entry").path();
                if path.is_dir() {
                    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if name != "target" && !name.starts_with('.') {
                        stack.push(path);
                    }
                } else if path.extension().is_some_and(|e| e == "rs")
                    && !path.ends_with("fa-model/src/entry.rs")
                {
                    scanned += 1;
                    let text = std::fs::read_to_string(&path).expect("read source");
                    for line in offending(&text) {
                        found.push(format!("{}: {line}", path.display()));
                    }
                }
            }
        }
        assert!(
            scanned > 50,
            "the scan reached the workspace ({scanned} files)"
        );
        assert!(
            found.is_empty(),
            "control kinds named by number: {found:#?}"
        );
    }

    #[test]
    fn code_classes_match_registry() {
        let reg = fa_registry::EntryClasses::embedded().unwrap();
        assert_eq!(reg.rows.len(), EntryClass::ALL.len());
        for row in &reg.rows {
            let c = EntryClass::from_name(&row.name).expect("class in code");
            assert_eq!(c.0, row.tag, "{}", row.name);
            assert_eq!(
                c.is_control(),
                row.kind == fa_registry::ClassKind::Control,
                "{}",
                row.name
            );
            assert_eq!(
                c.carries_open_items(),
                row.carries_open_items,
                "{}",
                row.name
            );
        }
    }

    #[test]
    fn envelope_round_trips_and_verifies() {
        let entry = proposal(two_legs())
            .seal(vec![], Some(Oid([2; 32])))
            .unwrap();
        let bytes = entry.encode().unwrap();
        let back = Entry::decode(&bytes).unwrap();
        assert_eq!(back, entry);
        assert_eq!(back.encode().unwrap(), bytes);
        assert_eq!(back.plan_certificate, Some(Oid([2; 32])));
        assert_eq!(
            back.proposal.description.open(&KEY, 1024).unwrap(),
            "Office rent, March"
        );
        assert_eq!(
            back.proposal.tags[0].value.open(&KEY, 1024).unwrap(),
            TagValue::Text("HQ".into())
        );
        assert_eq!(
            back.proposal.unit_totals,
            vec![UnitTotal {
                unit_id: 1,
                debits: 120_000,
                credits: 120_000
            }]
        );
    }

    /// fa-syy's negative: one changed leg changes `proposal_digest`, so any
    /// approval over the old digest no longer binds.
    #[test]
    fn changing_one_leg_changes_the_proposal_digest() {
        let a = proposal(two_legs()).proposal_digest().unwrap();
        let mut legs = two_legs();
        legs[0].amount.mantissa += 1;
        legs[1].amount.mantissa += 1;
        let mut p = proposal(legs);
        p.unit_totals = EntryPayload::fold_unit_totals(&p.legs).unwrap();
        assert_ne!(a, p.proposal_digest().unwrap());
    }

    /// The acyclic construction order: the plan certificate and the approvals
    /// change the envelope digest, never the proposal digest they are built
    /// from.
    #[test]
    fn envelope_fields_change_the_entry_digest_but_not_the_proposal_digest() {
        let p = proposal(two_legs());
        let e0 = p.clone().seal(vec![], None).unwrap();
        let e_cert = p.clone().seal(vec![], Some(Oid([2; 32]))).unwrap();
        let e_appr = p
            .seal(
                vec![ApprovalRef {
                    approval_vid: VId(500),
                    approved_digest: e0.proposal_digest,
                }],
                None,
            )
            .unwrap();
        assert_eq!(e0.proposal_digest, e_cert.proposal_digest);
        assert_eq!(e0.proposal_digest, e_appr.proposal_digest);
        assert_ne!(e0.entry_digest, e_cert.entry_digest);
        assert_ne!(e0.entry_digest, e_appr.entry_digest);
        assert_ne!(e_cert.entry_digest, e_appr.entry_digest);
        assert_eq!(
            Entry::decode(&e_appr.encode().unwrap())
                .unwrap()
                .approvals
                .len(),
            1
        );
    }

    /// Retry equivalence is plaintext-level: the same description sealed with
    /// a different salt changes the proposal digest but not the semantic
    /// digest; a different description changes both; a foreign key cannot
    /// claim equivalence at all.
    #[test]
    fn semantic_digest_sees_through_fresh_salts_and_refuses_foreign_keys() {
        let a = proposal(two_legs());
        let mut b = a.clone();
        b.description = Erasable::seal(
            &"Office rent, March".to_string(),
            None,
            &KEY,
            [9; 32],
            [8; 24],
        );
        let mut c = a.clone();
        c.description = Erasable::seal(
            &"Office rent, April".to_string(),
            None,
            &KEY,
            [1; 32],
            [2; 24],
        );
        assert_ne!(a.proposal_digest().unwrap(), b.proposal_digest().unwrap());
        assert_eq!(
            a.semantic_digest(&KEY).unwrap(),
            b.semantic_digest(&KEY).unwrap()
        );
        assert_ne!(
            a.semantic_digest(&KEY).unwrap(),
            c.semantic_digest(&KEY).unwrap()
        );
        assert!(matches!(
            a.semantic_digest(&SealKey([0; 32])).unwrap_err(),
            EntryError::Sealed(EraseError::Sealed)
        ));
        // The transcript is not the wire form: it never equals the proposal digest.
        assert_ne!(
            a.semantic_digest(&KEY).unwrap(),
            a.proposal_digest().unwrap()
        );
    }

    #[test]
    fn tampered_bytes_are_refused() {
        let entry = proposal(two_legs())
            .seal(vec![], Some(Oid([2; 32])))
            .unwrap();
        let bytes = entry.encode().unwrap();
        for i in 0..bytes.len() - 64 {
            let mut t = bytes.clone();
            t[i] ^= 0x01;
            assert!(
                Entry::decode(&t).is_err(),
                "byte {i} flipped and still decoded"
            );
        }
        let mut t = bytes.clone();
        let n = t.len();
        t[n - 1] ^= 1;
        assert_eq!(
            Entry::decode(&t).unwrap_err(),
            EntryError::DigestMismatch {
                which: "entry_digest"
            }
        );
        let mut t = bytes;
        t.push(0);
        assert!(matches!(
            Entry::decode(&t).unwrap_err(),
            EntryError::Decode(_)
        ));
    }

    #[test]
    fn structural_rules_are_enforced() {
        let one_leg = proposal(vec![LegPayload::simple(
            Side::Debit,
            VId(1),
            Amount::new(USD, 5),
        )]);
        assert_eq!(
            one_leg.validate().unwrap_err(),
            EntryError::Invalid {
                what: "legs",
                why: "a posting class has at least two legs"
            }
        );

        let mut neg = proposal(two_legs());
        neg.legs[0].amount.mantissa = -1;
        neg.unit_totals = vec![];
        assert!(matches!(
            neg.validate().unwrap_err(),
            EntryError::Invalid {
                what: "leg.amount",
                ..
            }
        ));

        // fa-cvg: `Dr 0 / Cr 0` balances but moves nothing; it is refused.
        let mut zero = proposal(two_legs());
        zero.legs[0].amount.mantissa = 0;
        zero.legs[1].amount.mantissa = 0;
        zero.unit_totals = vec![];
        assert!(matches!(
            zero.validate().unwrap_err(),
            EntryError::Invalid {
                what: "leg.amount",
                ..
            }
        ));

        let mut totals = proposal(two_legs());
        totals.unit_totals[0].debits += 1;
        assert_eq!(totals.validate().unwrap_err(), EntryError::TotalsMismatch);

        let mut key = proposal(two_legs());
        key.idempotency_key.clear();
        assert!(matches!(
            key.validate().unwrap_err(),
            EntryError::Invalid {
                what: "idempotency_key",
                ..
            }
        ));

        let mut unregistered = proposal(two_legs());
        unregistered.class = EntryClass(999);
        assert!(matches!(
            unregistered.validate().unwrap_err(),
            EntryError::Invalid { what: "class", .. }
        ));

        let mut control_with_legs = proposal(two_legs());
        control_with_legs.class = EntryClass::PERIOD_CONTROL;
        assert!(matches!(
            control_with_legs.validate().unwrap_err(),
            EntryError::Invalid { what: "legs", .. }
        ));

        let mut unsorted_tags = proposal(two_legs());
        unsorted_tags.tags.push(Tag {
            key: "aaa".into(),
            value: Erasable::seal(&TagValue::Null, None, &KEY, [0; 32], [0; 24]),
        });
        assert!(matches!(
            unsorted_tags.validate().unwrap_err(),
            EntryError::Invalid { what: "tags", .. }
        ));

        let big: Vec<LegPayload> = (0..MAX_LEGS_PER_ENTRY + 1)
            .map(|i| LegPayload::simple(Side::Debit, VId(i as u128), Amount::new(USD, 1)))
            .collect();
        assert!(matches!(
            proposal(big).validate().unwrap_err(),
            EntryError::Invalid { what: "legs", .. }
        ));
        // A tick past max_tick_utc_ns, or from an unregistered source, is
        // refused by its structural rule (fa-psz), not only by the kernel.
        for tick in [
            ControlPayload::TimeTick {
                observed_utc_ns: MAX_TICK_UTC_NS + 1,
                source: 0,
                monotonic_ok: true,
            },
            ControlPayload::TimeTick {
                observed_utc_ns: 1_700_000_000_000_000_000,
                source: 3,
                monotonic_ok: true,
            },
        ] {
            let mut p = proposal(vec![]);
            p.class = EntryClass::PERIOD_CONTROL;
            p.control = Some(tick);
            p.unit_totals = vec![];
            assert_eq!(
                p.validate().unwrap_err(),
                EntryError::Invalid {
                    what: "control.time_tick",
                    why: "source must be 0..=2 and observed_utc_ns within max_tick_utc_ns",
                }
            );
        }
    }

    /// A sealed field longer than its decode bound is refused before
    /// encoding: a 1,200-byte description once committed and then read back
    /// as Corrupt. The bound itself (1,024 bytes) still validates and
    /// round-trips.
    #[test]
    fn sealed_fields_beyond_their_decode_bound_are_refused() {
        let mut at_bound = proposal(two_legs());
        at_bound.description = desc(&"d".repeat(MAX_DESCRIPTION_BYTES));
        let bytes = at_bound.canonical_bytes().unwrap();
        let mut r = Reader::new(&bytes);
        assert_eq!(EntryPayload::decode_from(&mut r).unwrap(), at_bound);
        r.finish().unwrap();

        let mut long = proposal(two_legs());
        long.description = desc(&"d".repeat(MAX_DESCRIPTION_BYTES + 1));
        assert!(matches!(
            long.validate().unwrap_err(),
            EntryError::Invalid {
                what: "description",
                ..
            }
        ));
        assert!(long.canonical_bytes().is_err());

        let mut memo = proposal(two_legs());
        memo.legs[0].memo = Some(desc(&"m".repeat(MAX_MEMO_BYTES + 1)));
        assert!(matches!(
            memo.validate().unwrap_err(),
            EntryError::Invalid {
                what: "leg.memo",
                ..
            }
        ));

        let mut external = proposal(two_legs());
        external.external_ids.push(ExternalId {
            system: "erp".into(),
            id: desc(&"x".repeat(MAX_EXTERNAL_ID_BYTES + 1)),
        });
        assert!(matches!(
            external.validate().unwrap_err(),
            EntryError::Invalid {
                what: "external_ids.id",
                ..
            }
        ));

        let mut tag = proposal(two_legs());
        tag.tags[0].value = Erasable::seal(
            &TagValue::Text("t".repeat(MAX_TAG_BYTES_VALUE + 1)),
            None,
            &KEY,
            [5; 32],
            [6; 24],
        );
        assert!(matches!(
            tag.validate().unwrap_err(),
            EntryError::Invalid {
                what: "tags.value",
                ..
            }
        ));
    }

    #[test]
    fn overflowing_leg_sums_are_refused_not_wrapped() {
        let legs = vec![
            LegPayload::simple(Side::Debit, VId(1), Amount::new(USD, i128::MAX)),
            LegPayload::simple(Side::Debit, VId(2), Amount::new(USD, 1)),
        ];
        assert_eq!(
            EntryPayload::fold_unit_totals(&legs).unwrap_err(),
            EntryError::Overflow
        );
    }

    /// fa-bvx: a control record has `legs = []` and a `ControlPayload`, and
    /// every control variant round-trips.
    #[test]
    fn control_records_round_trip() {
        let variants = vec![
            ControlPayload::PeriodTransition {
                period_ref: PeriodRef {
                    calendar: "cal".into(),
                    code: "FY2026-P03".into(),
                },
                from: 1,
                to: 2,
                reason_code: 7,
                case_ref: Some(VId(3)),
            },
            ControlPayload::SchemaChange {
                kind: 2,
                canonical_bytes: vec![1, 2, 3],
            },
            ControlPayload::PolicyActivation {
                policy_oid: Oid([1; 32]),
                effective_from: DateDay(1),
                effective_to: DateDay(400),
            },
            ControlPayload::LifecycleTransition {
                object_ref: VId(4),
                from: 0,
                to: 1,
                proof_refs: vec![TypedRef::Vertex(VId(5)), TypedRef::Object(Oid([6; 32]))],
                reason_code: 1,
            },
            ControlPayload::TimeTick {
                observed_utc_ns: 1_700_000_000_000_000_000,
                source: 0,
                monotonic_ok: true,
            },
            ControlPayload::SweepCursor {
                sweep_kind: 1,
                last_pending_vid: VId(8),
                tick_ref: VId(9),
            },
            ControlPayload::ScheduleCancelled {
                schedule_ref: VId(10),
                cause_ref: VId(11),
            },
            ControlPayload::CapabilityEvent {
                commitment: [12; 32],
                kind: 1,
                caveats_digest: [13; 32],
            },
            ControlPayload::HoldEvent {
                scope_digest: [14; 32],
                authority_oid: Oid([15; 32]),
                kind: 0,
            },
            ControlPayload::ErasureCut {
                subject_ref: VId(16),
                field_digests: vec![[1; 32], [2; 32]],
            },
            ControlPayload::MigrationControl {
                run_ref: VId(17),
                kind: 2,
                tie_out_digest: [18; 32],
            },
        ];
        for control in variants {
            let mut p = proposal(vec![]);
            p.class = EntryClass::PERIOD_CONTROL;
            p.control = Some(control.clone());
            p.unit_totals = vec![];
            let e = p.seal(vec![], None).unwrap();
            let back = Entry::decode(&e.encode().unwrap()).unwrap();
            assert_eq!(back.proposal.control, Some(control));
            assert!(back.proposal.legs.is_empty());
        }
        let mut p = proposal(vec![]);
        p.class = EntryClass::POLICY_CONTROL;
        p.unit_totals = vec![];
        assert!(matches!(
            p.validate().unwrap_err(),
            EntryError::Invalid {
                what: "control",
                ..
            }
        ));
    }

    #[test]
    fn origins_pending_and_supersession_round_trip() {
        let mut p = proposal(two_legs());
        p.class = EntryClass::RESOLUTION;
        p.origin = EntryOrigin::Migration {
            run_ref: VId(1),
            source_system: "QuickBooks".into(),
            source_id: Erasable::seal(&"JE-77".to_string(), None, &KEY, [1; 32], [1; 24]),
            source_recorded_at_ns: Some(42),
            source_entered_by: Some(Erasable::seal(
                &"clerk".to_string(),
                Some(VId(2)),
                &KEY,
                [2; 32],
                [2; 24],
            )),
            source_approved_by: None,
            batch_oid: Oid([9; 32]),
        };
        p.legs[0].memo = Some(Erasable::seal(
            &"memo".to_string(),
            None,
            &KEY,
            [3; 32],
            [3; 24],
        ));
        p.pending = Some(Pending {
            timeout_ns: None,
            resolution_of: Some(EntryRef {
                vid: VId(3),
                entry_digest: [3; 32],
            }),
            disposition: Some(Disposition::Posts {
                source_ordinals: vec![0, 1],
            }),
        });
        p.supersession = vec![Supersession {
            target: EntryRef {
                vid: VId(4),
                entry_digest: [4; 32],
            },
            kind: SupersessionKind::Resolves,
            reason_code: 2,
        }];
        p.base_totals = Some(BaseTotals {
            unit_id: 1,
            debits: 120_000,
            credits: 120_000,
            fx_law_oid: Oid([5; 32]),
            rate_doc_oids: vec![Oid([1; 32]), Oid([2; 32])],
            residual: Some(Residual {
                leg_ordinal: 1,
                amount: Amount::new(USD, 1),
            }),
        });
        p.external_ids = vec![ExternalId {
            system: "bank".into(),
            id: Erasable::seal(&"TXN-9".to_string(), None, &KEY, [8; 32], [8; 24]),
        }];
        p.effective_period = Some(PeriodRef {
            calendar: "cal".into(),
            code: "FY2026-A1".into(),
        });
        let e = p.clone().seal(vec![], None).unwrap();
        let back = Entry::decode(&e.encode().unwrap()).unwrap();
        assert_eq!(back, e);
        // Every erasable field participates in the semantic transcript.
        assert!(p.semantic_digest(&KEY).is_ok());
        for v in [
            EntryOrigin::Rule {
                rule_version_oid: Oid([1; 32]),
                event_ref: VId(2),
                inputs_digest: [3; 32],
            },
            EntryOrigin::Control {
                control_kind: ControlKind::TIME_TICK,
                spec_body_digest: [5; 32],
            },
            EntryOrigin::Sweep {
                sweep_kind: 1,
                tick_evidence_oid: Oid([6; 32]),
            },
            EntryOrigin::Schedule {
                schedule_ref: VId(7),
                trigger: ScheduleTrigger::Sweep { tick_ref: VId(8) },
            },
            EntryOrigin::Schedule {
                schedule_ref: VId(7),
                trigger: ScheduleTrigger::OpenPeriod {
                    transition_ref: VId(9),
                },
            },
        ] {
            let mut p = proposal(two_legs());
            p.origin = v.clone();
            let e = p.seal(vec![], None).unwrap();
            assert_eq!(
                Entry::decode(&e.encode().unwrap()).unwrap().proposal.origin,
                v
            );
        }
    }

    /// fa-5dpd: extension 33 is registered, and validate judges its terms
    /// against the legs before anything posts. Terms on the credit leg whose
    /// installments total its 1,200.00 pass. Terms on the debit leg, on a leg
    /// the entry does not have, totalling 1.00 short, or bytes that do not
    /// decode are each refused.
    #[test]
    fn obligation_maturity_terms_are_validated_against_the_legs() {
        use crate::obligation::{InlineObligationTerms, ObligationInstallment, ObligationStatus};
        assert!(KNOWN_EXTENSION_TAGS.contains(&OBLIGATION_MATURITY_EXTENSION));
        let terms = |ordinal: u16, amount: i128| {
            InlineObligationTerms::to_extension(&[InlineObligationTerms {
                ordinal,
                status: ObligationStatus::Contractual,
                installments: vec![
                    ObligationInstallment {
                        due_date: DateDay(20_100),
                        amount: 20_000,
                    },
                    ObligationInstallment {
                        due_date: DateDay(20_400),
                        amount,
                    },
                ],
            }])
            .unwrap()
        };
        let with = |extension: (u16, Vec<u8>)| {
            let mut p = proposal(two_legs());
            p.extensions = vec![extension];
            p
        };
        let why = |p: EntryPayload| match p.validate() {
            Err(EntryError::Invalid {
                what: "extensions.obligation_maturity",
                why,
            }) => Some(why),
            _ => None,
        };
        with(terms(1, 100_000)).validate().unwrap();
        assert!(why(with(terms(0, 100_000))).is_some_and(|w| w.contains("debit leg")));
        assert!(why(with(terms(2, 100_000))).is_some_and(|w| w.contains("does not have")));
        assert!(why(with(terms(1, 99_900))).is_some_and(|w| w.contains("total exactly")));
        assert!(
            why(with((OBLIGATION_MATURITY_EXTENSION, vec![1, 2, 3])))
                .is_some_and(|w| w.contains("decode"))
        );
    }

    /// Additive-minor law: an unknown extension tag is refused at this
    /// reader's minor, preserved byte-for-byte at a higher one, and covered
    /// by the digests either way.
    #[test]
    fn extensions_follow_the_additive_minor_law() {
        // An unregistered tag (7–9 are registered since fa-v62/fa-s7x).
        let mut p = proposal(two_legs());
        p.extensions = vec![(999, vec![1, 2, 3])];
        assert!(matches!(
            p.validate().unwrap_err(),
            EntryError::Invalid {
                what: "extensions",
                ..
            }
        ));
        p.schema_minor = SCHEMA_MINOR + 1;
        // This build reads a newer writer's entry (it validates, preserving
        // the unknown tag), but never writes one (fa-hoi5): validate_for_write
        // and seal refuse the minor it does not know.
        assert!(p.validate().is_ok());
        for refused in [
            p.validate_for_write().unwrap_err(),
            p.clone().seal(vec![], None).unwrap_err(),
        ] {
            assert!(
                matches!(
                    refused,
                    EntryError::Invalid {
                        what: "schema_minor",
                        ..
                    }
                ),
                "{refused:?}"
            );
        }
        let e = p.clone().seal_unchecked(vec![], None).unwrap();
        let back = Entry::decode(&e.encode().unwrap()).unwrap();
        assert_eq!(back.proposal.extensions, vec![(999, vec![1, 2, 3])]);
        let mut q = p.clone();
        q.extensions = vec![(999, vec![1, 2, 4])];
        assert_ne!(q.proposal_digest().unwrap(), p.proposal_digest().unwrap());
        let mut unsorted = p.clone();
        unsorted.extensions = vec![(1000, vec![]), (999, vec![])];
        assert!(unsorted.validate().is_err());
        // A registered tag validates at this reader's minor.
        let mut known = proposal(two_legs());
        known.extensions = vec![(BALANCING_EXTENSION, vec![0; 18])];
        assert!(known.validate().is_ok());
        known.extensions = vec![
            (AUTO_REVERSE_EXTENSION, vec![0; 5]),
            (DATE_BASIS_EXTENSION, vec![0; 17]),
            (LEGAL_HOLD_SCOPE_EXTENSION, vec![1; 17]),
        ];
        assert!(known.validate().is_ok());
    }

    #[test]
    fn prior_period_adjustment_retains_its_source_and_binds_the_approved_digest() {
        let earlier = PeriodRef {
            calendar: "cal".into(),
            code: "FY2025-P12".into(),
        };
        for class in [
            EntryClass::ORIGINAL,
            EntryClass::ADJUSTING,
            EntryClass::PRIOR_PERIOD_ADJUSTMENT,
        ] {
            let mut p = proposal(two_legs());
            p.schema_minor = 0;
            p.class = class;
            p.with_prior_period_adjustment(&earlier).unwrap();
            assert_eq!(p.schema_minor, PRIOR_PERIOD_ADJUSTMENT_SCHEMA_MINOR);
            p.validate_for_write().unwrap();
            let entry = p.clone().seal(vec![], None).unwrap();
            let bytes = entry.encode().unwrap();
            let decoded = Entry::decode(&bytes).unwrap();
            assert_eq!(decoded.encode().unwrap(), bytes);
            assert_eq!(
                decoded.proposal.prior_period_adjustment().unwrap(),
                Some(PriorPeriodAdjustment {
                    relates_to: earlier.clone(),
                })
            );
            let digest = p.proposal_digest().unwrap();
            p.with_prior_period_adjustment(&PeriodRef {
                code: "FY2025-P11".into(),
                ..earlier.clone()
            })
            .unwrap();
            assert_eq!(
                p.extensions.len(),
                1,
                "replaces, never duplicates the claim"
            );
            assert_ne!(p.proposal_digest().unwrap(), digest);
        }
    }

    #[test]
    fn prior_period_adjustment_codec_rejects_malformed_or_misplaced_claims() {
        let prior = PriorPeriodAdjustment {
            relates_to: PeriodRef {
                calendar: "cal".into(),
                code: "FY2025-P12".into(),
            },
        };
        let canonical = prior.encode().unwrap();
        for length in 0..canonical.len() {
            assert!(PriorPeriodAdjustment::decode(&canonical[..length]).is_err());
        }
        let mut future_version = canonical.clone();
        future_version[0] = 2;
        let mut trailing = canonical;
        trailing.push(0);
        for invalid in [future_version, trailing] {
            assert!(PriorPeriodAdjustment::decode(&invalid).is_err());
        }
        for (calendar, code) in [
            (String::new(), "FY2025-P12".into()),
            ("cal".into(), String::new()),
            ("c".repeat(MAX_PERIOD_REF_BYTES + 1), "FY2025-P12".into()),
            ("cal".into(), "p".repeat(MAX_PERIOD_REF_BYTES + 1)),
        ] {
            let bytes = PriorPeriodAdjustment {
                relates_to: PeriodRef { calendar, code },
            }
            .encode()
            .unwrap();
            assert!(PriorPeriodAdjustment::decode(&bytes).is_err());
        }
        let mut p = proposal(two_legs());
        p.with_prior_period_adjustment(&prior.relates_to).unwrap();
        p.schema_minor = PRIOR_PERIOD_ADJUSTMENT_SCHEMA_MINOR - 1;
        assert!(matches!(
            p.validate_for_write(),
            Err(EntryError::Invalid {
                what: "extensions.prior_period_adjustment",
                ..
            })
        ));
        p.schema_minor = PRIOR_PERIOD_ADJUSTMENT_SCHEMA_MINOR;
        p.class = EntryClass::CLOSING;
        assert!(matches!(
            p.validate_for_write(),
            Err(EntryError::Invalid {
                what: "extensions.prior_period_adjustment",
                ..
            })
        ));
    }

    #[test]
    fn legacy_prior_period_adjustment_round_trips_without_an_invented_source() {
        let mut p = proposal(two_legs());
        p.class = EntryClass::PRIOR_PERIOD_ADJUSTMENT;
        p.schema_minor = 0;
        let historical = p.seal(vec![], None).unwrap();
        let bytes = historical.encode().unwrap();
        let decoded = Entry::decode(&bytes).unwrap();
        assert_eq!(decoded.encode().unwrap(), bytes);
        assert_eq!(decoded.proposal.prior_period_adjustment().unwrap(), None);
        assert_eq!(decoded.entry_digest, historical.entry_digest);
    }

    /// Disposition-sensitive arity (plan §5.4): a Pending carries a bare
    /// pending block; Resolution(Posts) posts a sub-vector with parallel
    /// ordinals; Resolution(Voids) carries no legs and the ReservationRelease
    /// control, which no control class may carry.
    #[test]
    fn pending_and_resolution_shapes_are_enforced() {
        let target = EntryRef {
            vid: VId(3),
            entry_digest: [3; 32],
        };
        let bare = Pending {
            timeout_ns: None,
            resolution_of: None,
            disposition: None,
        };
        let mut pending = proposal(two_legs());
        pending.class = EntryClass::PENDING;
        assert!(matches!(
            pending.validate().unwrap_err(),
            EntryError::Invalid {
                what: "pending",
                ..
            }
        ));
        pending.pending = Some(bare.clone());
        pending.validate().unwrap();

        let mut posts = proposal(two_legs());
        posts.class = EntryClass::RESOLUTION;
        posts.pending = Some(Pending {
            timeout_ns: None,
            resolution_of: Some(target),
            disposition: Some(Disposition::Posts {
                source_ordinals: vec![0, 1],
            }),
        });
        posts.validate().unwrap();
        let mut timed = posts.clone();
        timed.pending = Some(Pending {
            timeout_ns: Some(5),
            resolution_of: Some(target),
            disposition: Some(Disposition::Posts {
                source_ordinals: vec![0, 1],
            }),
        });
        assert!(matches!(
            timed.validate().unwrap_err(),
            EntryError::Invalid {
                what: "pending",
                ..
            }
        ));
        let mut bad = posts.clone();
        bad.pending = Some(Pending {
            timeout_ns: None,
            resolution_of: Some(target),
            disposition: Some(Disposition::Posts {
                source_ordinals: vec![1],
            }),
        });
        assert!(matches!(
            bad.validate().unwrap_err(),
            EntryError::Invalid {
                what: "pending.disposition",
                ..
            }
        ));

        let mut voids = proposal(vec![]);
        voids.class = EntryClass::RESOLUTION;
        voids.pending = Some(Pending {
            timeout_ns: None,
            resolution_of: Some(target),
            disposition: Some(Disposition::Voids),
        });
        assert!(matches!(
            voids.validate().unwrap_err(),
            EntryError::Invalid {
                what: "control",
                ..
            }
        ));
        voids.control = Some(ControlPayload::ReservationRelease);
        voids.validate().unwrap();
        let e = voids.clone().seal(vec![], None).unwrap();
        assert_eq!(Entry::decode(&e.encode().unwrap()).unwrap(), e);

        let mut on_control = voids;
        on_control.class = EntryClass::PERIOD_CONTROL;
        on_control.pending = None;
        assert!(matches!(
            on_control.validate().unwrap_err(),
            EntryError::Invalid {
                what: "control",
                ..
            }
        ));

        let mut stray = proposal(two_legs());
        stray.pending = Some(bare);
        assert!(matches!(
            stray.validate().unwrap_err(),
            EntryError::Invalid {
                what: "pending",
                ..
            }
        ));
    }

    /// Golden vectors: the digests of a fixed proposal are pinned so a codec
    /// change that moves bytes fails here before it reaches a book. The
    /// minor-0 vector is the original layout and is never re-pinned; the
    /// minor-1 vector adds the (empty) extension block of fa-rqe.
    #[test]
    fn digest_golden_vectors_per_minor() {
        let hex = |d: [u8; 32]| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let mut p = proposal(two_legs());
        p.schema_minor = 0;
        let e = p.clone().seal(vec![], None).unwrap();
        assert_eq!(
            (hex(e.proposal_digest), hex(e.entry_digest)),
            (
                "94b3431c8ebc79f6a786216e67942a12aed0b1fee090fa43f69fc3673caa2b24".to_string(),
                "3be6122714342ee45b11fda3e107965bbb25778ec942654a4347ca5a31e18b8a".to_string()
            )
        );
        let minor0 = e.encode().unwrap();
        p.schema_minor = 1;
        let e1 = p.seal(vec![], None).unwrap();
        assert_eq!(
            (hex(e1.proposal_digest), hex(e1.entry_digest)),
            (
                "507387780770c1f354bef0cd009cce6e8142bbd22de4793770dcdbb8abcc0ad3".to_string(),
                "b61584c562d45095a4bf212cb0ec1fa5752cb1bb67b9f8c52398dfb3ff6da64e".to_string()
            )
        );
        // Minor 1 is minor 0 plus exactly the empty extension block; both
        // decode, and the minor-0 bytes decode without any extension field.
        assert_eq!(Entry::decode(&minor0).unwrap(), e);
        assert!(
            Entry::decode(&minor0)
                .unwrap()
                .proposal
                .extensions
                .is_empty()
        );
        assert_eq!(Entry::decode(&e1.encode().unwrap()).unwrap(), e1);
    }
}
