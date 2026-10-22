//! Audit engagements (plan §0.4 decision 3, §11.12, Appendix A `Engagement`
//! and `ProposedAdjustment`, Appendix B `OpenEngagement`, `ProposeAdjustment`,
//! `BookAdjustment`, `PassAdjustment`; bead fa-zgn).
//!
//! An engagement's records are `EngagementControl` entries (class 29, control
//! kind 16), each a `LifecycleTransition`:
//!
//! - **Open** (`0 → Open` on the `Engagement` at [`fa_model::engagement_vid`])
//!   journals the profile (extension 17 `fa:engagement:v1`): its kind, the
//!   firm principal that opened it, its scope periods and the materiality
//!   parameters in the book's base unit. The parameters are stated by the
//!   auditor and never judged here. The vertex starts at `state = Open` and
//!   its `ordinal` property, the next proposal number, at 1. (An existing
//!   property key: a new label is the only symbol this class adds, so books
//!   created before it keep the label-prefix compatibility their retained
//!   certificates replay under.)
//! - **Propose** (`Open → Open` on the Engagement) journals a draft
//!   correcting entry (extension 18 `fa:proposed-adjustment:v1`): balanced per
//!   unit, on posting leaves effective at its date, dated inside a scope
//!   period. It never posts. It takes the next proposal number by
//!   compare-and-set and creates the `ProposedAdjustment` vertex at
//!   [`fa_model::proposed_adjustment_vid`] in state `Proposed`.
//! - **Book** (`Proposed → Booked` on the ProposedAdjustment) names, as its
//!   one proof ref, the committed trunk entry whose legs equal the proposal's.
//! - **Pass** (`Proposed → Passed` on the ProposedAdjustment) carries an
//!   `adjustment_pass` reason code (`reason_codes.toml`).
//! - **File** (`s → s` on the Engagement, no extension) puts one document
//!   the book holds, its one proof ref, in the engagement's workpaper index.
//! - **Complete** (`Open → DocumentationComplete` on the Engagement)
//!   journals the documentation completion once (extension 26
//!   `fa:documentation-completion:v1`): the report release date and a
//!   completion date at most 45 days after it (AS 1215.15). Every later
//!   Propose or File record is journaled in DocumentationComplete, so the
//!   record itself says it is an addition after completion (AS 1215.16);
//!   a later Book or Pass is one by journal order. Nothing is withdrawn.
//!
//! A decided proposal is never decided again (FA-REF-181): its state mirror
//! moves by compare-and-set, so two concurrent decisions cannot both commit.
//! Every record is a trunk record under the op `sod_policy.toml` registers
//! for its EngagementControl transition (`produce`), so an Agent prepares
//! none. Nothing here alters a committed amount.

use std::collections::BTreeMap;

use fa_model::entry::PRIOR_PERIOD_ERROR_EXTENSION;
use fa_model::symbols::{label, property, relation};
use fa_model::{
    ControlKind, ControlPayload, EntryClass, EntryOrigin, EntryPayload, Erasable, Id128, Oid,
    PeriodRef, Reader, TypedRef, Writer, domain_digest, engagement_vid, entry_mirrors, entry_vid,
    period_vid, proposed_adjustment_vid,
};
use fa_money::{Amount, Side, UnitId};
use fa_policy::{Capability, Intent};
use fa_time::DateDay;
use fgdb::{Database, VertexRow, WriteBatch, WriteMismatchPolicy, WriteTxn, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::genesis::{BookContext, UnitPolicy};
use crate::policy::{capability_witness, refusal as denial, steward};
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{AccountRow, PeriodRow, bytes, edge_id, prop, scalar_bytes, scalar_text};

/// Canonical bytes of an engagement profile (extension 17): `u16 version ‖
/// book_id[16] ‖ str engagement ‖ u8 kind ‖ u128 firm_principal ‖ list(str
/// period) ‖ u32 unit ‖ i128 overall ‖ i128 performance ‖ i128
/// clearly_trivial ‖ opt i32 report_release_day ‖ [32]
/// capability_commitment`.
pub const PROFILE_VERSION: u16 = 1;
/// Canonical bytes of a proposed adjustment (extension 18): `u16 version ‖
/// str engagement ‖ u32 ordinal ‖ i32 effective_day ‖ list(u8 side ‖ u128
/// account ‖ u32 unit ‖ i128 mantissa)`.
pub const PROPOSAL_VERSION: u16 = 1;
/// An engagement id's bound, in bytes.
pub const MAX_ENGAGEMENT_BYTES: usize = 128;
/// The scope periods one engagement may name.
pub const MAX_SCOPE_PERIODS: usize = 64;
/// A period code's bound, in bytes.
pub const MAX_PERIOD_CODE_BYTES: usize = 64;
/// The legs one proposed adjustment may carry.
pub const MAX_PROPOSAL_LEGS: usize = 256;
/// Canonical bytes of a documentation completion (extension 26): `u16
/// version ‖ i32 report_release_day ‖ i32 completion_day`.
pub const COMPLETION_VERSION: u16 = 1;
/// AS 1215.15: documentation is complete within 45 days after the report
/// release date.
pub const DOCUMENTATION_WINDOW_DAYS: i32 = 45;
/// Canonical bytes of a carry-forward (extension 28): `u16 version ‖ u128
/// prior engagement ‖ list(u32 turned-around) ‖ list(u32 corrected)`.
pub const CARRY_FORWARD_VERSION: u16 = 1;
/// The ordinals one carry-forward list may name.
pub const MAX_CARRIED_ORDINALS: usize = 4096;
const PROFILE_DOMAIN: &[u8] = b"fa:engagement:v1";
const CARRY_FORWARD_DOMAIN: &[u8] = b"fa:engagement-carry-forward:v1";
const PROPOSAL_DOMAIN: &[u8] = b"fa:proposed-adjustment:v1";
const COMPLETION_DOMAIN: &[u8] = b"fa:documentation-completion:v1";
const WORKPAPER_DOMAIN: &[u8] = b"fa:engagement-workpaper:v1";
const RECORD_KEY_DOMAIN: &[u8] = b"fa:engagement-record-key:v1";

/// The kind of engagement (Appendix A `Engagement.kind`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EngagementKind {
    Audit,
    Review,
    Examination,
    Investigation,
    Litigation,
}

impl EngagementKind {
    pub const ALL: [Self; 5] = [
        Self::Audit,
        Self::Review,
        Self::Examination,
        Self::Investigation,
        Self::Litigation,
    ];

    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            Self::Audit => 1,
            Self::Review => 2,
            Self::Examination => 3,
            Self::Investigation => 4,
            Self::Litigation => 5,
        }
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Audit => "audit",
            Self::Review => "review",
            Self::Examination => "examination",
            Self::Investigation => "investigation",
            Self::Litigation => "litigation",
        }
    }

    #[must_use]
    pub fn from_tag(tag: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.tag() == tag)
    }

    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.name() == name)
    }
}

/// The materiality parameters the auditor states for the engagement, in the
/// profile's unit (plan §11.12: parameters, never judgments).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Materiality {
    pub overall: i128,
    pub performance: i128,
    pub clearly_trivial: i128,
}

/// An engagement's immutable profile (Appendix A `Engagement`). Its
/// documentation-completion day is a later transition, not part of the
/// profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EngagementProfile {
    pub book_id: Id128,
    pub engagement: String,
    pub kind: EngagementKind,
    /// The principal that opened the engagement.
    pub firm_principal: VId,
    /// Sorted and unique period codes the engagement covers.
    pub scope_periods: Vec<String>,
    /// The unit the materiality parameters are stated in: the book's base
    /// unit at Open.
    pub unit: UnitId,
    pub materiality: Materiality,
    pub report_release_day: Option<DateDay>,
    /// The commitment of the capability that opened the engagement.
    pub capability_commitment: [u8; 32],
}

impl EngagementProfile {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, KernelError> {
        let mut w = Writer::with_capacity(160 + self.engagement.len());
        w.u16(PROFILE_VERSION)
            .fixed(&self.book_id.0)
            .str(&self.engagement)
            .u8(self.kind.tag())
            .u128(self.firm_principal.0)
            .list(&self.scope_periods, |w, p| {
                w.str(p);
            })
            .u32(self.unit.0)
            .i128(self.materiality.overall)
            .i128(self.materiality.performance)
            .i128(self.materiality.clearly_trivial)
            .opt(self.report_release_day.as_ref(), |w, d| {
                w.i32(d.0);
            })
            .fixed(&self.capability_commitment);
        Ok(w.finish()?)
    }

    /// Decode and validate a profile; refuses an unknown version, a field out
    /// of its domain, and trailing bytes.
    pub fn decode(raw: &[u8]) -> Result<Self, KernelError> {
        let mut r = Reader::new(raw);
        if r.u16("engagement.version").map_err(decode)? != PROFILE_VERSION {
            return Err(KernelError::Corrupt(
                "unsupported engagement profile version".into(),
            ));
        }
        let book_id = Id128(r.fixed("engagement.book_id").map_err(decode)?);
        let engagement = r
            .str(MAX_ENGAGEMENT_BYTES, "engagement.id")
            .map_err(decode)?
            .to_string();
        let tag = r.u8("engagement.kind").map_err(decode)?;
        let kind = EngagementKind::from_tag(tag)
            .ok_or_else(|| KernelError::Corrupt(format!("engagement kind {tag}")))?;
        let firm_principal = VId(r.u128("engagement.firm_principal").map_err(decode)?);
        let scope_periods = r
            .list(MAX_SCOPE_PERIODS, "engagement.scope_periods", |r| {
                Ok(r.str(MAX_PERIOD_CODE_BYTES, "engagement.period")?
                    .to_string())
            })
            .map_err(decode)?;
        let unit = UnitId(r.u32("engagement.unit").map_err(decode)?);
        let materiality = Materiality {
            overall: r.i128("engagement.overall").map_err(decode)?,
            performance: r.i128("engagement.performance").map_err(decode)?,
            clearly_trivial: r.i128("engagement.clearly_trivial").map_err(decode)?,
        };
        let report_release_day = r
            .opt("engagement.report_release_day", |r| {
                Ok(DateDay(r.i32("engagement.report_release_day")?))
            })
            .map_err(decode)?;
        let capability_commitment = r.fixed("engagement.capability").map_err(decode)?;
        r.finish().map_err(decode)?;
        let profile = Self {
            book_id,
            engagement,
            kind,
            firm_principal,
            scope_periods,
            unit,
            materiality,
            report_release_day,
            capability_commitment,
        };
        profile
            .check()
            .map_err(|why| KernelError::Corrupt(format!("engagement profile: {why}")))?;
        Ok(profile)
    }

    /// The field domains a profile must satisfy, as one sentence.
    pub fn check(&self) -> Result<(), String> {
        check_engagement(&self.engagement)?;
        if self.scope_periods.is_empty() || self.scope_periods.len() > MAX_SCOPE_PERIODS {
            return Err(format!(
                "an engagement covers 1..={MAX_SCOPE_PERIODS} scope periods"
            ));
        }
        if self.scope_periods.windows(2).any(|w| w[0] >= w[1])
            || self
                .scope_periods
                .iter()
                .any(|p| p.is_empty() || p.len() > MAX_PERIOD_CODE_BYTES)
        {
            return Err("scope periods are distinct, sorted period codes".into());
        }
        let m = self.materiality;
        if m.overall <= 0
            || m.performance <= 0
            || m.performance > m.overall
            || m.clearly_trivial < 0
            || m.clearly_trivial > m.performance
        {
            return Err(
                "materiality parameters need 0 <= clearly trivial <= performance <= overall, with performance and overall positive"
                    .into(),
            );
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<[u8; 32], KernelError> {
        Ok(domain_digest(PROFILE_DOMAIN, &[&self.canonical_bytes()?]))
    }

    #[must_use]
    pub fn vid(&self) -> VId {
        engagement_vid(self.book_id, &self.engagement)
    }
}

fn check_engagement(engagement: &str) -> Result<(), String> {
    if engagement.is_empty()
        || engagement.len() > MAX_ENGAGEMENT_BYTES
        || engagement.trim() != engagement
        || engagement.chars().any(char::is_control)
    {
        return Err(format!(
            "an engagement id is 1..={MAX_ENGAGEMENT_BYTES} bytes with no surrounding whitespace or control characters"
        ));
    }
    Ok(())
}

/// One leg of a proposed correcting entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProposalLeg {
    pub side: Side,
    pub account: VId,
    pub amount: Amount,
}

fn side_tag(side: Side) -> u8 {
    match side {
        Side::Debit => 0,
        Side::Credit => 1,
    }
}

/// A leg's canonical order: side, account, unit, amount.
fn leg_key(leg: &ProposalLeg) -> (u8, u128, u32, i128) {
    (
        side_tag(leg.side),
        leg.account.0,
        leg.amount.unit.0,
        leg.amount.mantissa,
    )
}

/// A draft correcting entry an engagement proposes (Appendix A
/// `ProposedAdjustment.draft_entry_payload`). Its description rides the
/// Propose record's sealed description; the bytes hold only structure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposedAdjustment {
    pub engagement: String,
    /// The proposal's number in its engagement, from 1.
    pub ordinal: u32,
    pub effective_date: DateDay,
    pub legs: Vec<ProposalLeg>,
}

impl ProposedAdjustment {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, KernelError> {
        let mut w = Writer::with_capacity(64 + self.legs.len() * 37);
        w.u16(PROPOSAL_VERSION)
            .str(&self.engagement)
            .u32(self.ordinal)
            .i32(self.effective_date.0)
            .list(&self.legs, |w, leg| {
                w.u8(side_tag(leg.side))
                    .u128(leg.account.0)
                    .u32(leg.amount.unit.0)
                    .i128(leg.amount.mantissa);
            });
        Ok(w.finish()?)
    }

    pub fn decode(raw: &[u8]) -> Result<Self, KernelError> {
        let mut r = Reader::new(raw);
        if r.u16("proposal.version").map_err(decode)? != PROPOSAL_VERSION {
            return Err(KernelError::Corrupt(
                "unsupported proposed adjustment version".into(),
            ));
        }
        let engagement = r
            .str(MAX_ENGAGEMENT_BYTES, "proposal.engagement")
            .map_err(decode)?
            .to_string();
        let ordinal = r.u32("proposal.ordinal").map_err(decode)?;
        let effective_date = DateDay(r.i32("proposal.effective_day").map_err(decode)?);
        let legs = r
            .list(MAX_PROPOSAL_LEGS, "proposal.legs", |r| {
                let side = match r.u8("proposal.side")? {
                    0 => Side::Debit,
                    1 => Side::Credit,
                    other => return Err(r.bad_tag("proposal.side", other)),
                };
                Ok(ProposalLeg {
                    side,
                    account: VId(r.u128("proposal.account")?),
                    amount: Amount::new(
                        UnitId(r.u32("proposal.unit")?),
                        r.i128("proposal.mantissa")?,
                    ),
                })
            })
            .map_err(decode)?;
        r.finish().map_err(decode)?;
        let proposal = Self {
            engagement,
            ordinal,
            effective_date,
            legs,
        };
        proposal
            .check()
            .map_err(|why| KernelError::Corrupt(format!("proposed adjustment: {why}")))?;
        Ok(proposal)
    }

    /// Two or more positive legs that balance in every unit.
    pub fn check(&self) -> Result<(), String> {
        check_engagement(&self.engagement)?;
        if self.ordinal == 0 {
            return Err("proposals are numbered from 1".into());
        }
        check_legs(&self.legs)
    }

    pub fn digest(&self) -> Result<[u8; 32], KernelError> {
        Ok(domain_digest(PROPOSAL_DOMAIN, &[&self.canonical_bytes()?]))
    }
}

/// An engagement's documentation completion (plan §11.12, AS 1215.15): the
/// report release date and the documentation completion date, which must lie
/// within [`DOCUMENTATION_WINDOW_DAYS`] days after it. Journaled once, by
/// the Complete record (extension 26).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DocumentationCompletion {
    pub report_release_day: DateDay,
    pub completion_day: DateDay,
}

impl DocumentationCompletion {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, KernelError> {
        let mut w = Writer::with_capacity(10);
        w.u16(COMPLETION_VERSION)
            .i32(self.report_release_day.0)
            .i32(self.completion_day.0);
        Ok(w.finish()?)
    }

    pub fn decode(raw: &[u8]) -> Result<Self, KernelError> {
        let mut r = Reader::new(raw);
        if r.u16("completion.version").map_err(decode)? != COMPLETION_VERSION {
            return Err(KernelError::Corrupt(
                "unsupported documentation completion version".into(),
            ));
        }
        let completion = Self {
            report_release_day: DateDay(r.i32("completion.report_release").map_err(decode)?),
            completion_day: DateDay(r.i32("completion.day").map_err(decode)?),
        };
        r.finish().map_err(decode)?;
        completion
            .check()
            .map_err(|why| KernelError::Corrupt(format!("documentation completion: {why}")))?;
        Ok(completion)
    }

    /// The completion date is on or after the report release date and at
    /// most [`DOCUMENTATION_WINDOW_DAYS`] days after it.
    pub fn check(&self) -> Result<(), String> {
        let after = self
            .completion_day
            .0
            .checked_sub(self.report_release_day.0)
            .ok_or_else(|| "the documentation completion dates overflow".to_string())?;
        if !(0..=DOCUMENTATION_WINDOW_DAYS).contains(&after) {
            return Err(format!(
                "the documentation completion date {} must lie within {DOCUMENTATION_WINDOW_DAYS} days after the report release date {} (AS 1215.15)",
                self.completion_day, self.report_release_day
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<[u8; 32], KernelError> {
        Ok(domain_digest(
            COMPLETION_DOMAIN,
            &[&self.canonical_bytes()?],
        ))
    }
}

/// Two or more legs with positive amounts whose debits equal their credits
/// in every unit, in exact checked arithmetic.
fn check_legs(legs: &[ProposalLeg]) -> Result<(), String> {
    if legs.len() < 2 || legs.len() > MAX_PROPOSAL_LEGS {
        return Err(format!(
            "a proposed adjustment has 2..={MAX_PROPOSAL_LEGS} legs"
        ));
    }
    let mut net: BTreeMap<u32, i128> = BTreeMap::new();
    for leg in legs {
        if leg.amount.mantissa <= 0 {
            return Err("every leg's amount is positive; its side carries the sign".into());
        }
        let slot = net.entry(leg.amount.unit.0).or_insert(0);
        *slot = match leg.side {
            Side::Debit => slot.checked_add(leg.amount.mantissa),
            Side::Credit => slot.checked_sub(leg.amount.mantissa),
        }
        .ok_or_else(|| "the legs' totals overflow".to_string())?;
    }
    if let Some((unit, gap)) = net.iter().find(|(_, net)| **net != 0) {
        return Err(format!(
            "the legs do not balance in unit {unit}: debits exceed credits by {gap} minor units"
        ));
    }
    Ok(())
}

fn decode(e: fa_model::DecodeError) -> KernelError {
    KernelError::Model(e.into())
}

/// An `Engagement`'s `state` projection: Open until its documentation
/// completion is journaled, then DocumentationComplete (AS 1215.15). A
/// record journaled in DocumentationComplete is an addition after
/// completion, and says so in its own `from`/`to` states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngagementState {
    Open,
    DocumentationComplete,
}

impl EngagementState {
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            Self::Open => 1,
            Self::DocumentationComplete => 2,
        }
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::DocumentationComplete => "documentation_complete",
        }
    }

    fn scalar(self) -> CanonicalScalar {
        CanonicalScalar::Int(i64::from(self.tag()))
    }

    fn from_scalar(v: Option<&CanonicalScalar>) -> Option<Self> {
        match v {
            Some(CanonicalScalar::Int(1)) => Some(Self::Open),
            Some(CanonicalScalar::Int(2)) => Some(Self::DocumentationComplete),
            _ => None,
        }
    }

    fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Open),
            2 => Some(Self::DocumentationComplete),
            _ => None,
        }
    }
}

/// A `ProposedAdjustment`'s `state` projection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdjustmentState {
    Proposed,
    Booked,
    Passed,
}

impl AdjustmentState {
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            Self::Proposed => 1,
            Self::Booked => 2,
            Self::Passed => 3,
        }
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Booked => "booked",
            Self::Passed => "passed",
        }
    }

    fn scalar(self) -> CanonicalScalar {
        CanonicalScalar::Int(i64::from(self.tag()))
    }

    fn from_scalar(v: Option<&CanonicalScalar>) -> Option<Self> {
        match v {
            Some(CanonicalScalar::Int(1)) => Some(Self::Proposed),
            Some(CanonicalScalar::Int(2)) => Some(Self::Booked),
            Some(CanonicalScalar::Int(3)) => Some(Self::Passed),
            _ => None,
        }
    }
}

/// An engagement control request: the acting capability, the record's
/// (undated, book-scoped) effective date, its sealed description and the
/// caller's idempotency key.
#[derive(Clone, Debug)]
pub struct EngagementRequest {
    pub capability: Capability,
    pub effective_date: DateDay,
    pub description: Erasable<String>,
    pub idempotency_key: Vec<u8>,
}

/// A recorded Open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EngagementOpened {
    pub engagement: VId,
    pub control_entry: VId,
    pub recorded_at: CommitSeq,
    /// The same Open was already journaled (FA-INV-09): nothing written.
    pub already_recorded: bool,
}

/// A recorded Propose.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdjustmentProposed {
    pub proposal: ProposedAdjustment,
    pub vid: VId,
    pub control_entry: VId,
    pub recorded_at: CommitSeq,
    pub already_recorded: bool,
}

/// How a proposal is decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdjustmentDecision {
    /// The committed trunk entry that makes the correction.
    Book { entry: VId },
    /// Left uncorrected, with its `adjustment_pass` reason code.
    Pass { reason_code: u16 },
}

impl AdjustmentDecision {
    fn kind(self) -> Kind {
        match self {
            Self::Book { .. } => Kind::Book,
            Self::Pass { .. } => Kind::Pass,
        }
    }

    fn state(self) -> AdjustmentState {
        match self {
            Self::Book { .. } => AdjustmentState::Booked,
            Self::Pass { .. } => AdjustmentState::Passed,
        }
    }
}

/// A recorded Book or Pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdjustmentDecided {
    pub proposal: VId,
    pub decision: AdjustmentDecision,
    pub control_entry: VId,
    pub recorded_at: CommitSeq,
    pub already_recorded: bool,
}

/// A decision as the journal states it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedDecision {
    pub decision: AdjustmentDecision,
    pub record: VId,
    pub recorded_at: CommitSeq,
    pub decided_by: VId,
    /// For a booking: the entry that has since reversed or replaced the
    /// booked entry, at the view's sequence. The correction no longer
    /// stands, so the proposal is uncorrected again (the decision itself
    /// stays on the record).
    pub superseded_by: Option<VId>,
    /// Decided after the documentation completion (by journal order).
    pub added_after_completion: bool,
}

/// A proposal as the journal states it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalView {
    pub vid: VId,
    pub proposal: ProposedAdjustment,
    pub record: VId,
    pub proposed_at: CommitSeq,
    pub proposed_by: VId,
    pub state: AdjustmentState,
    pub decision: Option<RecordedDecision>,
    /// Proposed after the documentation completion (its record says so).
    pub added_after_completion: bool,
}

/// An engagement's profile and every proposal its records journaled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EngagementView {
    pub vid: VId,
    pub profile: EngagementProfile,
    pub state: EngagementState,
    pub opened_at: CommitSeq,
    pub opened_by: VId,
    pub next_proposal: u32,
    /// By ordinal.
    pub proposals: Vec<ProposalView>,
    /// The workpaper index: every document filed in the engagement, in
    /// filing order.
    pub workpapers: Vec<WorkpaperView>,
    /// The journaled documentation completion, once there is one.
    pub documentation: Option<CompletionView>,
    /// Every carry-forward, in journal order; the last governs.
    pub carry_forwards: Vec<CarryForwardView>,
    /// The findings filed in the engagement's index, in filing order.
    pub findings: Vec<FindingInIndex>,
}

/// A Lantern finding filed in an engagement's index (plan §11.12: the
/// engagement's workpapers and findings are append-only after the
/// documentation completion).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingInIndex {
    /// The finding's vertex.
    pub finding: VId,
    pub record: VId,
    pub filed_at: CommitSeq,
    pub filed_by: VId,
    pub added_after_completion: bool,
}

/// A recorded File of a finding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingFiled {
    pub engagement: VId,
    pub finding: VId,
    pub control_entry: VId,
    pub recorded_at: CommitSeq,
    /// Filed after the documentation completion (AS 1215.16).
    pub added_after_completion: bool,
    /// The same filing was already journaled: nothing written.
    pub already_recorded: bool,
}

/// A recorded File: a document of the book in the engagement's workpaper
/// index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkpaperFiled {
    pub engagement: VId,
    pub document: Oid,
    pub control_entry: VId,
    pub recorded_at: CommitSeq,
    /// Filed after the documentation completion (AS 1215.16).
    pub added_after_completion: bool,
    /// The same filing was already journaled (FA-INV-09): nothing written.
    pub already_recorded: bool,
}

/// A recorded Complete.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DocumentationCompleted {
    pub engagement: VId,
    pub completion: DocumentationCompletion,
    pub control_entry: VId,
    pub recorded_at: CommitSeq,
    pub already_recorded: bool,
}

/// One workpaper as the journal states it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkpaperView {
    pub document: Oid,
    pub record: VId,
    pub filed_at: CommitSeq,
    pub filed_by: VId,
    pub added_after_completion: bool,
    /// The Confirmed attestation over the document, if it is a confirmation.
    pub confirmation: Option<WorkpaperConfirmation>,
    /// The Represented attestation over the document, if it is a
    /// representation letter.
    pub representation: Option<WorkpaperRepresentation>,
}

/// A confirmation in the workpaper index (AS 2310): what the party
/// confirmed, and whether it is audit-grade for this engagement — its firm
/// principal received the confirmation document, so the auditor
/// controlled it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkpaperConfirmation {
    pub attestation: VId,
    pub by_party: VId,
    pub balance: Amount,
    pub as_of: DateDay,
    pub attested_by: VId,
    pub received_by: Option<VId>,
    pub audit_grade: bool,
}

/// A management representation letter in the workpaper index (AS 2805):
/// how many claims it represents (each sealed) and as of when.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkpaperRepresentation {
    pub attestation: VId,
    pub claims: usize,
    pub as_of: DateDay,
    pub attested_by: VId,
}

/// The documentation completion as the journal states it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompletionView {
    pub completion: DocumentationCompletion,
    pub record: VId,
    pub recorded_at: CommitSeq,
    pub completed_by: VId,
}

/// An engagement's carry-forward of a prior engagement's uncorrected
/// misstatements (plan §11.12, SAB 108), as the auditor states it: which
/// prior items reversed through this period's income (turned around) and
/// which an out-of-period correction in this period corrected. Every other
/// uncorrected item of the prior engagement is still uncorrected at this
/// period's end. The prior engagement's own carry-forward is not chained.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CarryForward {
    /// The prior engagement's vertex.
    pub prior: VId,
    /// Strictly ascending ordinals of the prior engagement's proposals.
    pub turned_around: Vec<u32>,
    /// Strictly ascending, disjoint from `turned_around`.
    pub corrected: Vec<u32>,
}

impl CarryForward {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, KernelError> {
        let mut w =
            Writer::with_capacity(30 + 4 * (self.turned_around.len() + self.corrected.len()));
        w.u16(CARRY_FORWARD_VERSION).u128(self.prior.0);
        for list in [&self.turned_around, &self.corrected] {
            w.list(list, |w, ordinal| {
                w.u32(*ordinal);
            });
        }
        Ok(w.finish()?)
    }

    pub fn decode(raw: &[u8]) -> Result<Self, KernelError> {
        let mut r = Reader::new(raw);
        if r.u16("carry_forward.version").map_err(decode)? != CARRY_FORWARD_VERSION {
            return Err(KernelError::Corrupt(
                "unsupported carry-forward version".into(),
            ));
        }
        let prior = VId(r.u128("carry_forward.prior").map_err(decode)?);
        let mut lists = [Vec::new(), Vec::new()];
        for (list, field) in lists
            .iter_mut()
            .zip(["carry_forward.turned_around", "carry_forward.corrected"])
        {
            *list = r
                .list(MAX_CARRIED_ORDINALS, field, |r| r.u32(field))
                .map_err(decode)?;
        }
        r.finish().map_err(decode)?;
        let [turned_around, corrected] = lists;
        let carry_forward = Self {
            prior,
            turned_around,
            corrected,
        };
        carry_forward
            .check()
            .map_err(|why| KernelError::Corrupt(format!("carry-forward: {why}")))?;
        Ok(carry_forward)
    }

    /// Each list strictly ascending, within its bound, ordinals from 1, and
    /// no ordinal in both.
    pub fn check(&self) -> Result<(), String> {
        for (name, list) in [
            ("turned-around", &self.turned_around),
            ("corrected", &self.corrected),
        ] {
            if list.len() > MAX_CARRIED_ORDINALS {
                return Err(format!(
                    "{name} names {} proposals; at most {MAX_CARRIED_ORDINALS}",
                    list.len()
                ));
            }
            if list.first() == Some(&0) || list.windows(2).any(|w| w[0] >= w[1]) {
                return Err(format!(
                    "{name} proposals are numbered from 1, each named once"
                ));
            }
        }
        if let Some(both) = self
            .turned_around
            .iter()
            .find(|o| self.corrected.binary_search(o).is_ok())
        {
            return Err(format!(
                "prior proposal {both} is named both turned around and corrected"
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<[u8; 32], KernelError> {
        Ok(domain_digest(
            CARRY_FORWARD_DOMAIN,
            &[&self.canonical_bytes()?],
        ))
    }
}

/// A recorded CarryForward.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CarriedForward {
    pub engagement: VId,
    pub carry_forward: CarryForward,
    pub control_entry: VId,
    pub recorded_at: CommitSeq,
    /// Recorded after the documentation completion (AS 1215.16).
    pub added_after_completion: bool,
    /// The same carry-forward was already journaled: nothing written.
    pub already_recorded: bool,
}

/// A carry-forward as the journal states it. The latest one governs the
/// summary; earlier ones stay on the record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CarryForwardView {
    pub carry_forward: CarryForward,
    pub record: VId,
    pub recorded_at: CommitSeq,
    pub recorded_by: VId,
    pub added_after_completion: bool,
}

#[derive(Clone, Copy)]
enum Kind {
    Open,
    Propose,
    Book,
    Pass,
    File,
    Complete,
    CarryForward,
}

impl Kind {
    fn transition(self) -> &'static str {
        match self {
            Self::Open => "Open",
            Self::Propose => "Propose",
            Self::Book => "Book",
            Self::Pass => "Pass",
            Self::File => "File",
            Self::Complete => "Complete",
            Self::CarryForward => "CarryForward",
        }
    }

    fn tag(self) -> u8 {
        match self {
            Self::Open => 0,
            Self::Propose => 1,
            Self::Book => 2,
            Self::Pass => 3,
            Self::File => 4,
            Self::Complete => 5,
            Self::CarryForward => 6,
        }
    }

    /// `(from, to)` on the record's object: the Engagement for Open,
    /// Propose, File, Complete and CarryForward, the ProposedAdjustment for
    /// Book and Pass. Propose, File and CarryForward keep the engagement's
    /// state (`state`), so a record journaled after documentation completion
    /// says so; Complete moves it from Open to DocumentationComplete, once.
    fn states(self, state: EngagementState) -> (u8, u8) {
        let open = EngagementState::Open.tag();
        let proposed = AdjustmentState::Proposed.tag();
        match self {
            Self::Open => (0, open),
            Self::Propose | Self::File | Self::CarryForward => (state.tag(), state.tag()),
            Self::Complete => (open, EngagementState::DocumentationComplete.tag()),
            Self::Book => (proposed, AdjustmentState::Booked.tag()),
            Self::Pass => (proposed, AdjustmentState::Passed.tag()),
        }
    }
}

/// A record's idempotency key: `H(domain ‖ kind ‖ object ‖ caller key)`,
/// within the key bound whatever the caller's key.
fn record_key(kind: Kind, object: VId, key: &[u8]) -> Vec<u8> {
    domain_digest(
        RECORD_KEY_DOMAIN,
        &[&[kind.tag()], &object.0.to_le_bytes(), key],
    )
    .to_vec()
}

/// `state` is the engagement's state the record is journaled in (it decides
/// Propose's and File's `from`/`to`; the other kinds ignore it).
#[allow(clippy::too_many_arguments)]
fn record_proposal(
    book: &BookContext,
    kind: Kind,
    state: EngagementState,
    object: VId,
    spec_digest: [u8; 32],
    req: &EngagementRequest,
    proof_refs: Vec<TypedRef>,
    reason_code: u16,
    extension: Option<(u16, Vec<u8>)>,
) -> EntryPayload {
    let (from, to) = kind.states(state);
    EntryPayload {
        schema_minor: fa_model::entry::SCHEMA_MINOR,
        book_id: book.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::ENGAGEMENT_CONTROL,
        effective_date: req.effective_date,
        document_date: None,
        description: req.description.clone(),
        effective_period: None,
        legs: Vec::new(),
        control: Some(ControlPayload::LifecycleTransition {
            object_ref: object,
            from,
            to,
            proof_refs,
            reason_code,
        }),
        unit_totals: Vec::new(),
        base_totals: None,
        idempotency_key: record_key(kind, object, &req.idempotency_key),
        origin: EntryOrigin::Control {
            control_kind: ControlKind::ENGAGEMENT_TRANSITION,
            spec_body_digest: spec_digest,
        },
        principal_ref: req.capability.holder(),
        session_ref: None,
        evidence: Vec::new(),
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: extension.into_iter().collect(),
        tags: Vec::new(),
    }
}

/// Authority before any read (doctrine 8): the `EngagementControl` row's
/// preparer op for `kind`, held by the acting principal, current at the
/// head. An engagement record is a trunk record, so an Agent is refused.
fn admit<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    capability: &Capability,
    kind: Kind,
) -> Outcome<()> {
    let op = steward()?
        .transition_op("EngagementControl", kind.transition())
        .ok_or_else(|| {
            KernelError::Corrupt(format!(
                "sod_policy.toml registers no EngagementControl {} rule; the record is refused, never unconstrained",
                kind.transition()
            ))
        })?;
    if let Err(d) = fa_policy::admit(
        capability,
        &Intent {
            principal: capability.holder(),
            trunk: true,
            op,
            book: book.book_id,
            legs: &[],
        },
    ) {
        return Ok(Err(denial(&d)));
    }
    if let Err(d) = fa_policy::current(capability, db.frontier()?) {
        return Ok(Err(denial(&d)));
    }
    Ok(Ok(()))
}

fn usage(message: impl Into<String>, fix: &str) -> Refusal {
    Refusal::new(
        code::STRUCTURE,
        exit::USAGE,
        message.into(),
        "plan §11.12, Appendix A Engagement and ProposedAdjustment (bead fa-zgn)",
        fix,
    )
}

fn unknown(engagement: &str) -> Refusal {
    Refusal::new(
        code::ENGAGEMENT_UNKNOWN,
        exit::REFUSAL,
        format!("this book has no engagement `{engagement}`"),
        "plan §11.12 (an Engagement is the unit an audit's mechanics attach to)",
        "list the book's engagements with `fa engagement list --json`, or open one with `fa engagement open <id> --kind audit --period <code> --overall <amount> --performance <amount> --clearly-trivial <amount>`",
    )
}

fn unknown_proposal(engagement: &str, ordinal: u32) -> Refusal {
    Refusal::new(
        code::ADJUSTMENT_UNKNOWN,
        exit::REFUSAL,
        format!("engagement `{engagement}` has no proposed adjustment {ordinal}"),
        "plan §11.12, Appendix A ProposedAdjustment (numbered from 1 per engagement)",
        format!("list the engagement's proposals with `fa engagement show {engagement} --json`"),
    )
}

fn conflict_with(row: &VertexRow) -> Refusal {
    Refusal::new(
        code::IDEMPOTENCY_CONFLICT,
        exit::CONFLICT,
        format!(
            "this engagement record's identity holds different content; the recorded entry is {:032x}",
            row.vid.0
        ),
        "plan §4.9 (identity is derived from the key; content is bound by proposal_digest)",
        "resubmit the identical request to get its recorded outcome, or use a new --key",
    )
}

fn fcw(detail: &str) -> Refusal {
    Refusal::new(
        code::CONFLICT,
        exit::CONFLICT,
        format!("a concurrent commit invalidated a witness this engagement record read: {detail}"),
        "FG-LAW-FCW-01 (first committer wins)",
        "retry; read the engagement again with `fa engagement show <id> --json` first",
    )
}

/// The identical record's sequence, or the conflict (plan §4.9: exact bytes,
/// else a seal-aware semantic comparison under the book key).
fn recorded_or_conflict(
    book: &BookContext,
    row: &VertexRow,
    proposal: &EntryPayload,
) -> Outcome<CommitSeq> {
    let (stored, recorded_at) = crate::post::entry_of(row)?;
    if stored.proposal_digest == proposal.proposal_digest()? {
        return Ok(Ok(recorded_at));
    }
    match (
        stored.proposal.semantic_digest(&book.seal_key),
        proposal.semantic_digest(&book.seal_key),
    ) {
        (Ok(a), Ok(b)) if a == b => Ok(Ok(recorded_at)),
        (Ok(_), Ok(_)) => Ok(Err(conflict_with(row))),
        (Err(fa_model::EntryError::Sealed(_)), _) | (_, Err(fa_model::EntryError::Sealed(_))) => {
            Ok(Err(Refusal::new(
                code::EQUIVALENCE_UNVERIFIABLE,
                exit::CONFLICT,
                format!(
                    "the recorded engagement record {:032x} has erased text, so a retry cannot be judged identical",
                    row.vid.0
                ),
                "plan §4.9, §14.6 (erasure leaves identity, not plaintext)",
                "use a new --key",
            )))
        }
        (Err(e), _) | (_, Err(e)) => Err(e.into()),
    }
}

fn profile_of(row: &VertexRow) -> Result<EngagementProfile, KernelError> {
    EngagementProfile::decode(&bytes(row, property::FA_PAYLOAD, "engagement._fa_payload")?)
}

fn proposal_of(row: &VertexRow) -> Result<ProposedAdjustment, KernelError> {
    ProposedAdjustment::decode(&bytes(row, property::FA_PAYLOAD, "proposal._fa_payload")?)
}

fn next_of(value: Option<&CanonicalScalar>, engagement: VId) -> Result<u32, KernelError> {
    match value {
        Some(CanonicalScalar::Int(n)) if *n >= 1 => u32::try_from(*n).map_err(|_| {
            KernelError::Corrupt(format!(
                "engagement {:032x} next_proposal is out of range",
                engagement.0
            ))
        }),
        _ => Err(KernelError::Corrupt(format!(
            "engagement {:032x} carries no next_proposal",
            engagement.0
        ))),
    }
}

/// The engagement's vertex, checked to be one, and its profile.
fn engagement_row(
    txn: &WriteTxn,
    db: &Database<impl asupersync::fs::Vfs + Clone>,
    vid: VId,
) -> Result<Option<(VertexRow, EngagementProfile)>, KernelError> {
    let Some(row) = txn.vertex(db, vid)? else {
        return Ok(None);
    };
    if !row.labels.contains(&label::ENGAGEMENT) {
        return Err(KernelError::Corrupt(format!(
            "engagement identity {:032x} holds a vertex that is not an Engagement",
            vid.0
        )));
    }
    let profile = profile_of(&row)?;
    if profile.vid() != vid {
        return Err(KernelError::Corrupt(format!(
            "engagement {:032x} carries another engagement's body",
            vid.0
        )));
    }
    Ok(Some((row, profile)))
}

/// Open `profile.engagement`: one commit journaling the Open record, the
/// `Engagement` vertex with its immutable profile, `state = Open` and its
/// next proposal number (`ordinal`) at 1, and the record's `IN_CASE` edge to
/// it. Every scope
/// period must exist, and the parameters are stated in the base unit.
pub async fn open_engagement<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    profile: EngagementProfile,
    req: EngagementRequest,
) -> Outcome<EngagementOpened> {
    const FIX: &str = "fa engagement open <id> --kind audit|review|examination|investigation|litigation --period <code>... --overall <amount> --performance <amount> --clearly-trivial <amount>";
    if profile.book_id != book.book_id {
        return Ok(Err(usage("the engagement profile names another book", FIX)));
    }
    if profile.firm_principal != req.capability.holder() {
        return Ok(Err(usage(
            "an engagement's firm principal is the principal that opens it",
            FIX,
        )));
    }
    let commitment = req
        .capability
        .commitment()
        .map_err(|e| KernelError::Corrupt(format!("capability commitment: {e:?}")))?;
    if profile.capability_commitment != commitment {
        return Ok(Err(usage(
            "an engagement binds the commitment of the capability that opens it",
            FIX,
        )));
    }
    if let Err(why) = profile.check() {
        return Ok(Err(usage(why, FIX)));
    }
    if let Err(r) = admit(db, book, &req.capability, Kind::Open)? {
        return Ok(Err(r));
    }
    let base_unit = crate::genesis::read_book_spec(db)?
        .ok_or_else(|| KernelError::Corrupt("the store holds no book spec".into()))?
        .base_unit;
    if profile.unit != base_unit {
        return Ok(Err(usage(
            "materiality parameters are stated in the book's base unit",
            FIX,
        )));
    }
    let body = profile.canonical_bytes()?;
    let vid = profile.vid();
    let proposal = record_proposal(
        book,
        Kind::Open,
        EngagementState::Open,
        vid,
        profile.digest()?,
        &req,
        Vec::new(),
        0,
        Some((fa_model::entry::ENGAGEMENT_PROFILE_EXTENSION, body.clone())),
    );
    if proposal.validate().is_err() {
        return Ok(Err(usage(
            "the Open record is not a valid EngagementControl entry",
            FIX,
        )));
    }
    let evid = entry_vid(
        book.book_id,
        &proposal.principal_ref.0.to_le_bytes(),
        &proposal.idempotency_key,
    );
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    // The capability is not revoked (plan §14.2): the first read.
    if let Err(r) = capability_witness(&txn, db, book, &req.capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    if let Some(row) = txn.vertex(db, evid)? {
        txn.abort();
        return Ok(
            recorded_or_conflict(book, &row, &proposal)?.map(|recorded_at| EngagementOpened {
                engagement: vid,
                control_entry: evid,
                recorded_at,
                already_recorded: true,
            }),
        );
    }
    if txn.vertex(db, vid)?.is_some() {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::IDEMPOTENCY_CONFLICT,
            exit::CONFLICT,
            format!("engagement `{}` is already open", profile.engagement),
            "plan §11.12 (one Engagement per id in a book; its profile is immutable)",
            "inspect it with `fa engagement show <id> --json`, or open a new engagement under another id",
        )));
    }
    for code_text in &profile.scope_periods {
        let Some(row) = txn.vertex(db, period_vid(&book.calendar.id, code_text))? else {
            txn.abort();
            return Ok(Err(Refusal::new(
                code::PERIOD_UNKNOWN,
                exit::SAFETY,
                format!("scope period `{code_text}` does not exist in this book"),
                "plan §7.2 (periods are created per fiscal year), §11.12 (an engagement's scope periods)",
                "list the book's periods with `fa period list --json`",
            )));
        };
        PeriodRow::decode(&row)?;
    }
    let entry = proposal.clone().seal(Vec::new(), None)?;
    let mut props = vec![
        (
            property::FA_PAYLOAD,
            scalar_bytes("engagement._fa_payload", body)?,
        ),
        (
            property::FA_DIGEST,
            scalar_bytes("engagement._fa_digest", profile.digest()?.to_vec())?,
        ),
        (
            property::BOOK_ID,
            scalar_bytes("book_id", book.book_id.0.to_vec())?,
        ),
        (
            property::CODE,
            scalar_text("engagement.code", &profile.engagement)?,
        ),
        (property::STATE, EngagementState::Open.scalar()),
        (property::ORDINAL, CanonicalScalar::Int(1)),
    ];
    props.sort_by_key(|(k, _)| k.0);
    let mut in_case = WriteBatch::new(relation::IN_CASE);
    in_case.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    in_case.create_vertex(vid, vec![label::ENGAGEMENT], props);
    in_case.add_edge(edge_id(relation::IN_CASE, evid, vid), evid, vid, vec![]);
    txn.write(db, in_case)?;
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(EngagementOpened {
            engagement: vid,
            control_entry: evid,
            recorded_at: seq,
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(fcw(&detail)))
        }
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => match db.vertex(evid)? {
            Some(row) => Ok(
                recorded_or_conflict(book, &row, &proposal)?.map(|recorded_at| EngagementOpened {
                    engagement: vid,
                    control_entry: evid,
                    recorded_at,
                    already_recorded: true,
                }),
            ),
            None => Ok(Err(fcw("the engagement was opened concurrently"))),
        },
        Err(e) => Err(e.into()),
    }
}

/// A leg's account: an account of this book, a posting leaf effective at
/// `day`, accepting the leg's registered unit (the posting kernel's checks,
/// applied to a draft that never posts).
fn check_leg_account<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    book: &BookContext,
    i: usize,
    leg: &ProposalLeg,
    day: DateDay,
) -> Outcome<()> {
    let Some(row) = txn.vertex(db, leg.account)? else {
        return Ok(Err(Refusal::new(
            code::UNKNOWN_ACCOUNT,
            exit::REFUSAL,
            format!("leg {i} names an account this book does not have"),
            "plan §4.3",
            "fa chart list --json to find the account",
        )));
    };
    if !row.labels.contains(&label::ACCOUNT) {
        return Ok(Err(Refusal::new(
            code::UNKNOWN_ACCOUNT,
            exit::REFUSAL,
            format!("leg {i} names a vertex that is not an account of this book"),
            "plan §4.3",
            "fa chart list --json to find the account",
        )));
    }
    let account = AccountRow::decode(&row)?;
    if !account.is_leaf {
        return Ok(Err(Refusal::new(
            code::NOT_A_LEAF,
            exit::REFUSAL,
            format!("leg {i} names `{}`, a summary account", account.code),
            "plan §4.3 (only leaves accept legs)",
            format!("propose against a leaf under `{}`", account.code),
        )));
    }
    let effectivity = crate::chart::AccountEffectivity::decode_from_row(&row)?;
    if !effectivity.is_effective_at(day) {
        return Ok(Err(Refusal::new(
            code::NOT_A_LEAF,
            exit::REFUSAL,
            format!(
                "leg {i} names `{}` on {day}, outside its effective interval",
                account.code
            ),
            "FA-INV-01.account-effective (plan §4.3, §5.6)",
            format!(
                "date the proposal within `{}`'s open interval",
                account.code
            ),
        )));
    }
    let Some(unit) = book.units.get(leg.amount.unit) else {
        return Ok(Err(Refusal::new(
            code::UNIT_UNREGISTERED,
            exit::REFUSAL,
            format!(
                "leg {i}: unit id {} is not registered in this book",
                leg.amount.unit.0
            ),
            "plan §4.4 (amounts are mantissas at a registered unit version's scale)",
            "propose in a unit registered in registries/units.toml",
        )));
    };
    let unit_ok = match account.unit_policy {
        UnitPolicy::Single(u) => u == leg.amount.unit,
        UnitPolicy::AnyCurrency => matches!(unit.kind, fa_money::UnitKind::Currency { .. }),
        UnitPolicy::AnyUnit => true,
    };
    if !unit_ok {
        return Ok(Err(Refusal::new(
            code::UNIT_POLICY,
            exit::REFUSAL,
            format!(
                "leg {i}: account `{}` does not accept unit {}",
                account.code, unit.code
            ),
            "plan §4.3 unit_policy",
            "propose in the account's unit",
        )));
    }
    Ok(Ok(()))
}

/// The scope period whose interval holds `day`, if any.
fn scope_period_of<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    book: &BookContext,
    profile: &EngagementProfile,
    day: DateDay,
) -> Result<Option<String>, KernelError> {
    for code_text in &profile.scope_periods {
        let Some(row) = txn.vertex(db, period_vid(&book.calendar.id, code_text))? else {
            return Err(KernelError::Corrupt(format!(
                "engagement `{}` names scope period `{code_text}`, which has no vertex",
                profile.engagement
            )));
        };
        let period = PeriodRow::decode(&row)?;
        if period.start <= day && day <= period.end {
            return Ok(Some(code_text.clone()));
        }
    }
    Ok(None)
}

/// Propose a draft correcting entry in `engagement`: one commit journaling
/// the Propose record (extension 18), the `ProposedAdjustment` vertex at the
/// engagement's next number in state Proposed, the record's `IN_CASE` edges
/// to both, and `next_proposal + 1` by compare-and-set. Nothing posts.
pub async fn propose_adjustment<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    engagement: &str,
    effective_date: DateDay,
    legs: Vec<ProposalLeg>,
    req: EngagementRequest,
) -> Outcome<AdjustmentProposed> {
    const FIX: &str = "fa adjustment propose --engagement <id> --intent <entry.json>: two or more legs that balance in every unit, dated inside a scope period";
    if let Err(why) = check_engagement(engagement).and_then(|()| check_legs(&legs)) {
        return Ok(Err(usage(why, FIX)));
    }
    if let Err(r) = admit(db, book, &req.capability, Kind::Propose)? {
        return Ok(Err(r));
    }
    let vid = engagement_vid(book.book_id, engagement);
    let key = record_key(Kind::Propose, vid, &req.idempotency_key);
    let evid = entry_vid(book.book_id, &req.capability.holder().0.to_le_bytes(), &key);
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    if let Err(r) = capability_witness(&txn, db, book, &req.capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    let Some((_, profile)) = engagement_row(&txn, db, vid)? else {
        txn.abort();
        return Ok(Err(unknown(engagement)));
    };
    if let Some(stored) = txn.vertex(db, evid)? {
        txn.abort();
        return recorded_proposal(db, book, &stored, effective_date, &legs, &req);
    }
    // A point read of the state: a documentation completion that commits
    // first makes this a first-committer conflict, so the record's states
    // always say whether it was added after completion.
    let Some(state) =
        EngagementState::from_scalar(txn.vertex_property(db, vid, property::STATE)?.as_ref())
    else {
        txn.abort();
        return Err(KernelError::Corrupt(format!(
            "engagement {:032x} state mirror",
            vid.0
        )));
    };
    let Some(_) = scope_period_of(&txn, db, book, &profile, effective_date)? else {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::ADJUSTMENT_OUT_OF_SCOPE,
            exit::REFUSAL,
            format!(
                "{effective_date} is outside engagement `{engagement}`'s scope periods ({})",
                profile.scope_periods.join(", ")
            ),
            "plan §11.12 (an Engagement's scope_periods bound what its adjustments correct)",
            "date the proposed adjustment inside one of the engagement's scope periods",
        )));
    };
    for (i, leg) in legs.iter().enumerate() {
        if let Err(r) = check_leg_account(&txn, db, book, i, leg, effective_date)? {
            txn.abort();
            return Ok(Err(r));
        }
    }
    // Property-granular point read: a concurrent proposal that takes this
    // number first makes this transaction a first-committer conflict.
    let read_next = txn.vertex_property(db, vid, property::ORDINAL)?;
    let ordinal = next_of(read_next.as_ref(), vid)?;
    let Some(after) = ordinal.checked_add(1) else {
        txn.abort();
        return Ok(Err(usage(
            format!("engagement `{engagement}` has numbered every proposal it can"),
            "open a new engagement",
        )));
    };
    let proposal = ProposedAdjustment {
        engagement: engagement.to_string(),
        ordinal,
        effective_date,
        legs,
    };
    let body = proposal.canonical_bytes()?;
    let pvid = proposed_adjustment_vid(book.book_id, engagement, ordinal);
    let record = record_proposal(
        book,
        Kind::Propose,
        state,
        vid,
        proposal.digest()?,
        &req,
        vec![TypedRef::Vertex(pvid)],
        0,
        Some((fa_model::entry::PROPOSED_ADJUSTMENT_EXTENSION, body.clone())),
    );
    if record.validate().is_err() {
        txn.abort();
        return Ok(Err(usage(
            "the Propose record is not a valid EngagementControl entry",
            FIX,
        )));
    }
    if txn.vertex(db, pvid)?.is_some() {
        txn.abort();
        return Err(KernelError::Corrupt(format!(
            "engagement `{engagement}` proposal {ordinal} exists ahead of next_proposal"
        )));
    }
    let entry = record.clone().seal(Vec::new(), None)?;
    let mut batch = WriteBatch::new(relation::IN_CASE);
    batch.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    let mut props = vec![
        (
            property::FA_PAYLOAD,
            scalar_bytes("proposal._fa_payload", body)?,
        ),
        (
            property::BOOK_ID,
            scalar_bytes("book_id", book.book_id.0.to_vec())?,
        ),
        (property::STATE, AdjustmentState::Proposed.scalar()),
    ];
    props.sort_by_key(|(k, _)| k.0);
    batch.create_vertex(pvid, vec![label::PROPOSED_ADJUSTMENT], props);
    batch.add_edge(edge_id(relation::IN_CASE, evid, vid), evid, vid, vec![]);
    batch.add_edge(edge_id(relation::IN_CASE, evid, pvid), evid, pvid, vec![]);
    batch.compare_and_set_vertex_property(
        vid,
        property::ORDINAL,
        read_next,
        CanonicalScalar::Int(i64::from(after)),
        WriteMismatchPolicy::AbortWrite,
    );
    if let Err(e) = txn.write(db, batch) {
        txn.abort();
        return Err(e.into());
    }
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(AdjustmentProposed {
            proposal,
            vid: pvid,
            control_entry: evid,
            recorded_at: seq,
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(fcw(&detail)))
        }
        Err(WriteTxnError::Write(fgdb::WriteError::CompareAndSetMismatch(_))) => {
            Ok(Err(fcw("the engagement's next proposal number moved")))
        }
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => match db.vertex(evid)? {
            Some(stored) => {
                recorded_proposal(db, book, &stored, effective_date, &proposal.legs, &req)
            }
            None => Ok(Err(fcw("another proposal took this number concurrently"))),
        },
        Err(e) => Err(e.into()),
    }
}

/// The outcome of a Propose record already journaled under this request's
/// identity: the identical request gets its recorded proposal; any other
/// request under the same key is a conflict.
fn recorded_proposal<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    stored: &VertexRow,
    effective_date: DateDay,
    legs: &[ProposalLeg],
    req: &EngagementRequest,
) -> Outcome<AdjustmentProposed> {
    let (entry, _) = crate::post::entry_of(stored)?;
    let Some(recorded) = proposal_record(&entry)? else {
        return Ok(Err(conflict_with(stored)));
    };
    // The request as it would have been recorded at the stored number: the
    // identical request matches the stored record exactly (description
    // included, seal-aware); anything else under this key is a conflict.
    let proposal = ProposedAdjustment {
        engagement: recorded.engagement.clone(),
        ordinal: recorded.ordinal,
        effective_date,
        legs: legs.to_vec(),
    };
    let vid = engagement_vid(book.book_id, &proposal.engagement);
    let pvid = proposed_adjustment_vid(book.book_id, &proposal.engagement, proposal.ordinal);
    // The state the stored record was journaled in, which a retry after
    // documentation completion does not change.
    let state = match &entry.proposal.control {
        Some(ControlPayload::LifecycleTransition { from, .. }) => EngagementState::from_tag(*from),
        _ => None,
    };
    let Some(state) = state else {
        return Ok(Err(conflict_with(stored)));
    };
    let candidate = record_proposal(
        book,
        Kind::Propose,
        state,
        vid,
        proposal.digest()?,
        req,
        vec![TypedRef::Vertex(pvid)],
        0,
        Some((
            fa_model::entry::PROPOSED_ADJUSTMENT_EXTENSION,
            proposal.canonical_bytes()?,
        )),
    );
    let recorded_at = match recorded_or_conflict(book, stored, &candidate)? {
        Ok(seq) => seq,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if db.vertex(pvid)?.is_none() {
        return Err(KernelError::Corrupt(format!(
            "Propose record {:032x} has no ProposedAdjustment vertex",
            stored.vid.0
        )));
    }
    Ok(Ok(AdjustmentProposed {
        proposal,
        vid: pvid,
        control_entry: stored.vid,
        recorded_at,
        already_recorded: true,
    }))
}

/// An `EngagementControl` Propose record's proposal; `None` for any other
/// entry.
fn proposal_record(entry: &fa_model::Entry) -> Result<Option<ProposedAdjustment>, KernelError> {
    if entry.proposal.class != EntryClass::ENGAGEMENT_CONTROL {
        return Ok(None);
    }
    let Some((_, ext)) = entry
        .proposal
        .extensions
        .iter()
        .find(|(tag, _)| *tag == fa_model::entry::PROPOSED_ADJUSTMENT_EXTENSION)
    else {
        return Ok(None);
    };
    ProposedAdjustment::decode(ext).map(Some)
}

/// The legs a committed entry posts, as proposal legs, sorted.
fn posted_legs(entry: &fa_model::Entry) -> Vec<ProposalLeg> {
    let mut legs: Vec<ProposalLeg> = entry
        .proposal
        .legs
        .iter()
        .map(|leg| ProposalLeg {
            side: leg.side,
            account: leg.account_ref,
            amount: leg.amount,
        })
        .collect();
    legs.sort_by_key(leg_key);
    legs
}

/// Decide proposal `ordinal` of `engagement`: Book names the committed trunk
/// entry whose legs equal the proposal's (as a multiset), Pass records an
/// `adjustment_pass` reason. One commit journals the record, its `IN_CASE`
/// edge to the ProposedAdjustment, and the proposal's state by
/// compare-and-set from Proposed, so it is decided once.
pub async fn decide_adjustment<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    engagement: &str,
    ordinal: u32,
    decision: AdjustmentDecision,
    req: EngagementRequest,
) -> Outcome<AdjustmentDecided> {
    if let Err(why) = check_engagement(engagement) {
        return Ok(Err(usage(
            why,
            "fa adjustment book|pass --engagement <id> --proposal <n>",
        )));
    }
    if let AdjustmentDecision::Pass { reason_code } = decision {
        let reasons = fa_registry::reason_codes::ReasonCodes::embedded()
            .map_err(|e| KernelError::Corrupt(format!("reason registry: {e}")))?;
        if reasons.get("adjustment_pass", reason_code).is_none() {
            return Ok(Err(Refusal::new(
                code::REASON_CODE,
                exit::USAGE,
                format!("reason {reason_code} is not a registered adjustment_pass reason"),
                "reason_codes.toml scope adjustment_pass (plan §11.12)",
                format!("pass with one of: {}", reasons.listing("adjustment_pass")),
            )));
        }
    }
    let kind = decision.kind();
    if let Err(r) = admit(db, book, &req.capability, kind)? {
        return Ok(Err(r));
    }
    // Booking reads the entry it names (its legs, date, class and
    // supersession): authorization precedes that observation.
    if matches!(decision, AdjustmentDecision::Book { .. })
        && let Err(d) = fa_policy::require(
            &req.capability,
            fa_policy::Op::Read,
            "booking a proposed adjustment reads the entry it names",
        )
    {
        return Ok(Err(denial(&d)));
    }
    let vid = engagement_vid(book.book_id, engagement);
    let pvid = proposed_adjustment_vid(book.book_id, engagement, ordinal);
    let key = record_key(kind, pvid, &req.idempotency_key);
    let evid = entry_vid(book.book_id, &req.capability.holder().0.to_le_bytes(), &key);
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    if let Err(r) = capability_witness(&txn, db, book, &req.capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    let Some((_, profile)) = engagement_row(&txn, db, vid)? else {
        txn.abort();
        return Ok(Err(unknown(engagement)));
    };
    let Some(prow) = txn.vertex(db, pvid)? else {
        txn.abort();
        return Ok(Err(unknown_proposal(engagement, ordinal)));
    };
    if !prow.labels.contains(&label::PROPOSED_ADJUSTMENT) {
        txn.abort();
        return Err(KernelError::Corrupt(format!(
            "proposal identity {:032x} holds a vertex that is not a ProposedAdjustment",
            pvid.0
        )));
    }
    let proposal = proposal_of(&prow)?;
    if proposal.engagement != engagement || proposal.ordinal != ordinal {
        txn.abort();
        return Err(KernelError::Corrupt(format!(
            "proposal {:032x} carries another proposal's body",
            pvid.0
        )));
    }
    let (proof_refs, reason_code) = match decision {
        AdjustmentDecision::Book { entry } => (vec![TypedRef::Vertex(entry)], 0),
        AdjustmentDecision::Pass { reason_code } => (Vec::new(), reason_code),
    };
    // A decision's states are the proposal's; whether it came after the
    // engagement's documentation completion is its journal order.
    let record = record_proposal(
        book,
        kind,
        EngagementState::Open,
        pvid,
        proposal.digest()?,
        &req,
        proof_refs,
        reason_code,
        None,
    );
    if let Some(stored) = txn.vertex(db, evid)? {
        txn.abort();
        return Ok(
            recorded_or_conflict(book, &stored, &record)?.map(|recorded_at| AdjustmentDecided {
                proposal: pvid,
                decision,
                control_entry: evid,
                recorded_at,
                already_recorded: true,
            }),
        );
    }
    let read_state = txn.vertex_property(db, pvid, property::STATE)?;
    match AdjustmentState::from_scalar(read_state.as_ref()) {
        Some(AdjustmentState::Proposed) => {}
        Some(state) => {
            txn.abort();
            return Ok(Err(Refusal::new(
                code::ADJUSTMENT_DECIDED,
                exit::REFUSAL,
                format!(
                    "engagement `{engagement}` proposal {ordinal} is already {}",
                    state.name()
                ),
                "plan §11.12, Appendix A ProposedAdjustment (Proposed, then Booked or Passed once)",
                "the decided proposal stays on the record; propose a new adjustment with `fa adjustment propose` if the correction must change",
            )));
        }
        None => {
            txn.abort();
            return Err(KernelError::Corrupt(format!(
                "proposal {:032x} state mirror",
                pvid.0
            )));
        }
    }
    if let AdjustmentDecision::Book { entry } = decision {
        let Some(row) = txn.vertex(db, entry)? else {
            txn.abort();
            return Ok(Err(differs(
                engagement,
                ordinal,
                "names an entry this book does not have",
            )));
        };
        if !row.labels.contains(&label::ENTRY) {
            txn.abort();
            return Ok(Err(differs(
                engagement,
                ordinal,
                "names a vertex that is not an entry",
            )));
        }
        let (booked, booked_at) = crate::post::entry_of(&row)?;
        if booked.proposal.book_id != book.book_id
            || booked.proposal.branch_id != Id128::TRUNK
            || booked.proposal.class.is_control()
        {
            txn.abort();
            return Ok(Err(differs(
                engagement,
                ordinal,
                "names an entry that is not a committed trunk posting",
            )));
        }
        // A pending entry can still be voided or expire, and a migration
        // chunk carries history in: neither is the correction itself.
        if booked.proposal.class == EntryClass::PENDING
            || booked.proposal.class == EntryClass::MIGRATION
        {
            txn.abort();
            return Ok(Err(differs(
                engagement,
                ordinal,
                "names a pending or migrated entry, which is not a correction: book the posting that makes it",
            )));
        }
        let mut wanted = proposal.legs.clone();
        wanted.sort_by_key(leg_key);
        if posted_legs(&booked) != wanted {
            txn.abort();
            return Ok(Err(differs(
                engagement,
                ordinal,
                "names an entry whose legs differ from the proposal's",
            )));
        }
        // The correction follows its proposal, in the period it corrects.
        if booked_at <= prow.created_at {
            txn.abort();
            return Ok(Err(differs(
                engagement,
                ordinal,
                &format!(
                    "names an entry recorded at sequence {}, before the proposal (sequence {}): a correction follows what it corrects",
                    booked_at.0, prow.created_at.0
                ),
            )));
        }
        let Some(period) = scope_period_of(&txn, db, book, &profile, proposal.effective_date)?
        else {
            txn.abort();
            return Err(KernelError::Corrupt(format!(
                "proposal {:032x} is dated outside its engagement's scope periods",
                pvid.0
            )));
        };
        if scope_period_of(&txn, db, book, &profile, booked.proposal.effective_date)?.as_ref()
            != Some(&period)
        {
            txn.abort();
            return Ok(Err(differs(
                engagement,
                ordinal,
                &format!(
                    "names an entry effective {}, outside the proposal's period {period}",
                    booked.proposal.effective_date.render()
                ),
            )));
        }
        // A reversed or replaced entry no longer makes the correction. Both
        // identities are point reads, so a concurrent reversal conflicts at
        // commit (first committer wins).
        for identity in [
            crate::rows::reversal_vid(entry),
            crate::rows::replacement_vid(entry),
        ] {
            if let Some(superseder) = txn.vertex(db, identity)?
                && superseder.labels.contains(&label::ENTRY)
            {
                txn.abort();
                return Ok(Err(differs(
                    engagement,
                    ordinal,
                    &format!(
                        "names an entry superseded by entry {:032x}: book the correction that stands",
                        superseder.vid.0
                    ),
                )));
            }
        }
        // One committed entry makes one correction: it books no other
        // proposal of the engagement. Each other proposal's state is a
        // point-read witness, so a concurrent booking of the same entry
        // conflicts at commit (first committer wins).
        let next = next_of(
            txn.vertex_property(db, vid, property::ORDINAL)?.as_ref(),
            vid,
        )?;
        let seq = db.frontier()?;
        for other in (1..next).filter(|other| *other != ordinal) {
            let ovid = proposed_adjustment_vid(book.book_id, engagement, other);
            let state = txn.vertex_property(db, ovid, property::STATE)?;
            if AdjustmentState::from_scalar(state.as_ref()) == Some(AdjustmentState::Booked)
                && decision_of(db, ovid, seq)?.is_some_and(|d| d.decision == decision)
            {
                txn.abort();
                return Ok(Err(differs(
                    engagement,
                    ordinal,
                    &format!("names the entry that already books proposal {other}"),
                )));
            }
        }
    }
    if record.validate().is_err() {
        txn.abort();
        return Ok(Err(usage(
            "the decision record is not a valid EngagementControl entry",
            "fa adjustment book|pass --engagement <id> --proposal <n>",
        )));
    }
    let entry = record.clone().seal(Vec::new(), None)?;
    let mut batch = WriteBatch::new(relation::IN_CASE);
    batch.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    batch.add_edge(edge_id(relation::IN_CASE, evid, pvid), evid, pvid, vec![]);
    batch.compare_and_set_vertex_property(
        pvid,
        property::STATE,
        read_state,
        decision.state().scalar(),
        WriteMismatchPolicy::AbortWrite,
    );
    if let Err(e) = txn.write(db, batch) {
        txn.abort();
        return Err(e.into());
    }
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(AdjustmentDecided {
            proposal: pvid,
            decision,
            control_entry: evid,
            recorded_at: seq,
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(fcw(&detail)))
        }
        Err(WriteTxnError::Write(fgdb::WriteError::CompareAndSetMismatch(_))) => {
            Ok(Err(fcw("the proposal was decided concurrently")))
        }
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => {
            match db.vertex(evid)? {
                Some(stored) => Ok(recorded_or_conflict(book, &stored, &record)?.map(
                    |recorded_at| AdjustmentDecided {
                        proposal: pvid,
                        decision,
                        control_entry: evid,
                        recorded_at,
                        already_recorded: true,
                    },
                )),
                None => Ok(Err(fcw("the proposal was decided concurrently"))),
            }
        }
        Err(e) => Err(e.into()),
    }
}

/// A document this book holds, verified, for the engagement's workpaper
/// index.
fn witness_workpaper<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    document: &Oid,
) -> Outcome<()> {
    let policy = fa_registry::evidence_policy::EvidencePolicy::embedded()
        .map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let Some(row) = txn.vertex(db, crate::evidence::document_vid(document))? else {
        return Ok(Err(Refusal::new(
            code::EVIDENCE_UNKNOWN,
            exit::REFUSAL,
            format!(
                "workpaper document {} is not in this book",
                crate::evidence::hex(&document.0)
            ),
            "plan §11.12 (an engagement's workpaper index lists documents the book holds)",
            "record it first with `fa document add <file> --kind Workpaper --json` and file the oid it prints",
        )));
    };
    match crate::evidence::verify_row(&row, &policy) {
        Ok(_) => Ok(Ok(())),
        Err(why) => Ok(Err(crate::evidence::drift(document, &why))),
    }
}

fn completion_refused(why: impl Into<String>) -> Refusal {
    Refusal::new(
        code::DOCUMENTATION_COMPLETION,
        exit::REFUSAL,
        why.into(),
        "plan §11.12, AS 1215.15 (documentation is complete within 45 days after the report release date, once)",
        "fa engagement complete <id> --completion-date YYYY-MM-DD [--report-release YYYY-MM-DD], with the completion date within 45 days after the report release date; `fa engagement show <id> --json` shows the engagement's state",
    )
}

/// File `document` in `engagement`'s workpaper index (plan §11.12): one
/// commit journaling the File record, whose one proof ref is the document,
/// and its `IN_CASE` edge to the engagement. The document must be one this
/// book holds, verified, and not already in the index. The record's
/// identity derives from the document, so the same filing retried is the
/// same record. Filed after the documentation completion, the record is
/// journaled in DocumentationComplete: an addition after completion, which
/// the index marks (AS 1215.16); nothing filed is ever withdrawn.
pub async fn file_workpaper<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    engagement: &str,
    document: Oid,
    req: EngagementRequest,
) -> Outcome<WorkpaperFiled> {
    const FIX: &str = "fa engagement file <id> --document <oid>";
    if let Err(why) = check_engagement(engagement) {
        return Ok(Err(usage(why, FIX)));
    }
    if let Err(r) = admit(db, book, &req.capability, Kind::File)? {
        return Ok(Err(r));
    }
    let vid = engagement_vid(book.book_id, engagement);
    let key = record_key(Kind::File, vid, &document.0);
    let evid = entry_vid(book.book_id, &req.capability.holder().0.to_le_bytes(), &key);
    let spec_digest = domain_digest(WORKPAPER_DOMAIN, &[&vid.0.to_le_bytes(), &document.0]);
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    if let Err(r) = capability_witness(&txn, db, book, &req.capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    if engagement_row(&txn, db, vid)?.is_none() {
        txn.abort();
        return Ok(Err(unknown(engagement)));
    }
    // A point read of the state: a completion that commits first makes this
    // a first-committer conflict, so the record says which side it is on.
    let read_state = txn.vertex_property(db, vid, property::STATE)?;
    let Some(state) = EngagementState::from_scalar(read_state.as_ref()) else {
        txn.abort();
        return Err(KernelError::Corrupt(format!(
            "engagement {:032x} state mirror",
            vid.0
        )));
    };
    if let Some(stored) = txn.vertex(db, evid)? {
        txn.abort();
        let (entry, _) = crate::post::entry_of(&stored)?;
        let stored_state = match &entry.proposal.control {
            Some(ControlPayload::LifecycleTransition { from, .. }) => {
                EngagementState::from_tag(*from)
            }
            _ => None,
        };
        let Some(stored_state) = stored_state else {
            return Ok(Err(conflict_with(&stored)));
        };
        let record = record_proposal(
            book,
            Kind::File,
            stored_state,
            vid,
            spec_digest,
            &req,
            vec![TypedRef::Object(document)],
            0,
            None,
        );
        return Ok(
            recorded_or_conflict(book, &stored, &record)?.map(|recorded_at| WorkpaperFiled {
                engagement: vid,
                document,
                control_entry: evid,
                recorded_at,
                added_after_completion: stored_state == EngagementState::DocumentationComplete,
                already_recorded: true,
            }),
        );
    }
    if let Err(r) = witness_workpaper(&txn, db, &document)? {
        txn.abort();
        return Ok(Err(r));
    }
    let seq = db.frontier()?;
    for (record, entry, recorded_at, _, _) in records_into(db, vid, seq)? {
        if let Some(ControlPayload::LifecycleTransition { proof_refs, .. }) =
            &entry.proposal.control
            && entry.proposal.extensions.is_empty()
            && proof_refs.as_slice() == [TypedRef::Object(document)]
        {
            txn.abort();
            return Ok(Err(usage(
                format!(
                    "document {} is already in engagement `{engagement}`'s workpaper index (record {:032x}, at {})",
                    crate::evidence::hex(&document.0),
                    record.0,
                    recorded_at.0
                ),
                "file each document once; `fa engagement show <id> --json` lists the index",
            )));
        }
    }
    let record = record_proposal(
        book,
        Kind::File,
        state,
        vid,
        spec_digest,
        &req,
        vec![TypedRef::Object(document)],
        0,
        None,
    );
    if record.validate().is_err() {
        txn.abort();
        return Ok(Err(usage(
            "the File record is not a valid EngagementControl entry",
            FIX,
        )));
    }
    let entry = record.clone().seal(Vec::new(), None)?;
    let mut batch = WriteBatch::new(relation::IN_CASE);
    batch.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    batch.add_edge(edge_id(relation::IN_CASE, evid, vid), evid, vid, vec![]);
    if let Err(e) = txn.write(db, batch) {
        txn.abort();
        return Err(e.into());
    }
    let added_after_completion = state == EngagementState::DocumentationComplete;
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(WorkpaperFiled {
            engagement: vid,
            document,
            control_entry: evid,
            recorded_at: seq,
            added_after_completion,
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(fcw(&detail)))
        }
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => match db.vertex(evid)? {
            Some(stored) => Ok(
                recorded_or_conflict(book, &stored, &record)?.map(|recorded_at| WorkpaperFiled {
                    engagement: vid,
                    document,
                    control_entry: evid,
                    recorded_at,
                    added_after_completion,
                    already_recorded: true,
                }),
            ),
            None => Ok(Err(fcw("the workpaper was filed concurrently"))),
        },
        Err(e) => Err(e.into()),
    }
}

/// File the Lantern finding `finding` in `engagement`'s index (plan §11.12:
/// workpapers and findings are append-only after the documentation
/// completion): one commit journaling a File record whose one proof ref is
/// the finding's vertex, and its `IN_CASE` edge to the engagement. The
/// finding must be one this book holds and not already in the index; its
/// record's identity derives from the finding, so the same filing retried is
/// the same record. Filed after the completion, it is marked
/// `added_after_completion`.
pub async fn file_finding<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    engagement: &str,
    finding: VId,
    req: EngagementRequest,
) -> Outcome<FindingFiled> {
    const FIX: &str = "fa engagement file <id> --finding <vid> (fa finding list --json names them)";
    if let Err(why) = check_engagement(engagement) {
        return Ok(Err(usage(why, FIX)));
    }
    if let Err(r) = admit(db, book, &req.capability, Kind::File)? {
        return Ok(Err(r));
    }
    let vid = engagement_vid(book.book_id, engagement);
    let key = record_key(Kind::File, vid, &finding.0.to_le_bytes());
    let evid = entry_vid(book.book_id, &req.capability.holder().0.to_le_bytes(), &key);
    let spec_digest = domain_digest(
        WORKPAPER_DOMAIN,
        &[&vid.0.to_le_bytes(), &finding.0.to_le_bytes()],
    );
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    if let Err(r) = capability_witness(&txn, db, book, &req.capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    if engagement_row(&txn, db, vid)?.is_none() {
        txn.abort();
        return Ok(Err(unknown(engagement)));
    }
    let read_state = txn.vertex_property(db, vid, property::STATE)?;
    let Some(state) = EngagementState::from_scalar(read_state.as_ref()) else {
        txn.abort();
        return Err(KernelError::Corrupt(format!(
            "engagement {:032x} state mirror",
            vid.0
        )));
    };
    let record_in = |state: EngagementState| {
        record_proposal(
            book,
            Kind::File,
            state,
            vid,
            spec_digest,
            &req,
            vec![TypedRef::Vertex(finding)],
            0,
            None,
        )
    };
    if let Some(stored) = txn.vertex(db, evid)? {
        txn.abort();
        let (entry, _) = crate::post::entry_of(&stored)?;
        let stored_state = match &entry.proposal.control {
            Some(ControlPayload::LifecycleTransition { from, .. }) => {
                EngagementState::from_tag(*from)
            }
            _ => None,
        };
        let Some(stored_state) = stored_state else {
            return Ok(Err(conflict_with(&stored)));
        };
        return Ok(
            recorded_or_conflict(book, &stored, &record_in(stored_state))?.map(|recorded_at| {
                FindingFiled {
                    engagement: vid,
                    finding,
                    control_entry: evid,
                    recorded_at,
                    added_after_completion: stored_state == EngagementState::DocumentationComplete,
                    already_recorded: true,
                }
            }),
        );
    }
    let is_finding = txn
        .vertex(db, finding)?
        .is_some_and(|row| row.labels.contains(&label::FINDING));
    if !is_finding {
        txn.abort();
        return Ok(Err(usage(
            format!("{:032x} is not a finding of this book", finding.0),
            FIX,
        )));
    }
    let seq = db.frontier()?;
    for (record, entry, recorded_at, _, _) in records_into(db, vid, seq)? {
        if let Some(ControlPayload::LifecycleTransition { proof_refs, .. }) =
            &entry.proposal.control
            && entry.proposal.extensions.is_empty()
            && proof_refs.as_slice() == [TypedRef::Vertex(finding)]
        {
            txn.abort();
            return Ok(Err(usage(
                format!(
                    "finding {:032x} is already in engagement `{engagement}`'s index (record {:032x}, at {})",
                    finding.0, record.0, recorded_at.0
                ),
                "file each finding once; `fa engagement show <id> --json` lists the index",
            )));
        }
    }
    let record = record_in(state);
    if record.validate().is_err() {
        txn.abort();
        return Ok(Err(usage(
            "the File record is not a valid EngagementControl entry",
            FIX,
        )));
    }
    let entry = record.clone().seal(Vec::new(), None)?;
    let mut batch = WriteBatch::new(relation::IN_CASE);
    batch.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    batch.add_edge(edge_id(relation::IN_CASE, evid, vid), evid, vid, vec![]);
    if let Err(e) = txn.write(db, batch) {
        txn.abort();
        return Err(e.into());
    }
    let added_after_completion = state == EngagementState::DocumentationComplete;
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(FindingFiled {
            engagement: vid,
            finding,
            control_entry: evid,
            recorded_at: seq,
            added_after_completion,
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(fcw(&detail)))
        }
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => match db.vertex(evid)? {
            Some(stored) => Ok(
                recorded_or_conflict(book, &stored, &record)?.map(|recorded_at| FindingFiled {
                    engagement: vid,
                    finding,
                    control_entry: evid,
                    recorded_at,
                    added_after_completion,
                    already_recorded: true,
                }),
            ),
            None => Ok(Err(fcw("the finding was filed concurrently"))),
        },
        Err(e) => Err(e.into()),
    }
}

/// Journal `engagement`'s documentation completion (plan §11.12, AS
/// 1215.15): one commit journaling the Complete record (extension 26: the
/// report release date and the completion date, at most 45 days after it)
/// and moving the engagement from Open to DocumentationComplete by
/// compare-and-set, once. The report release date is the profile's when it
/// states one (`report_release` must then match or be absent), else
/// `report_release`. Every later record of the engagement is an addition
/// after completion.
pub async fn complete_documentation<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    engagement: &str,
    report_release: Option<DateDay>,
    completion_day: DateDay,
    req: EngagementRequest,
) -> Outcome<DocumentationCompleted> {
    const FIX: &str =
        "fa engagement complete <id> --completion-date YYYY-MM-DD [--report-release YYYY-MM-DD]";
    if let Err(why) = check_engagement(engagement) {
        return Ok(Err(usage(why, FIX)));
    }
    if let Err(r) = admit(db, book, &req.capability, Kind::Complete)? {
        return Ok(Err(r));
    }
    let vid = engagement_vid(book.book_id, engagement);
    let key = record_key(Kind::Complete, vid, &req.idempotency_key);
    let evid = entry_vid(book.book_id, &req.capability.holder().0.to_le_bytes(), &key);
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    if let Err(r) = capability_witness(&txn, db, book, &req.capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    let Some((_, profile)) = engagement_row(&txn, db, vid)? else {
        txn.abort();
        return Ok(Err(unknown(engagement)));
    };
    let report_release_day = match (profile.report_release_day, report_release) {
        (Some(stated), Some(given)) if stated != given => {
            txn.abort();
            return Ok(Err(completion_refused(format!(
                "engagement `{engagement}` states its report release date as {stated}; {given} differs"
            ))));
        }
        (Some(stated), _) => stated,
        (None, Some(given)) => given,
        (None, None) => {
            txn.abort();
            return Ok(Err(completion_refused(format!(
                "engagement `{engagement}` states no report release date; name it with --report-release"
            ))));
        }
    };
    let completion = DocumentationCompletion {
        report_release_day,
        completion_day,
    };
    if let Err(why) = completion.check() {
        txn.abort();
        return Ok(Err(completion_refused(why)));
    }
    let record = record_proposal(
        book,
        Kind::Complete,
        EngagementState::Open,
        vid,
        completion.digest()?,
        &req,
        Vec::new(),
        0,
        Some((
            fa_model::entry::DOCUMENTATION_COMPLETION_EXTENSION,
            completion.canonical_bytes()?,
        )),
    );
    if let Some(stored) = txn.vertex(db, evid)? {
        txn.abort();
        return Ok(
            recorded_or_conflict(book, &stored, &record)?.map(|recorded_at| {
                DocumentationCompleted {
                    engagement: vid,
                    completion,
                    control_entry: evid,
                    recorded_at,
                    already_recorded: true,
                }
            }),
        );
    }
    let read_state = txn.vertex_property(db, vid, property::STATE)?;
    match EngagementState::from_scalar(read_state.as_ref()) {
        Some(EngagementState::Open) => {}
        Some(EngagementState::DocumentationComplete) => {
            txn.abort();
            return Ok(Err(completion_refused(format!(
                "engagement `{engagement}`'s documentation completion is already journaled; it is recorded once"
            ))));
        }
        None => {
            txn.abort();
            return Err(KernelError::Corrupt(format!(
                "engagement {:032x} state mirror",
                vid.0
            )));
        }
    }
    if record.validate().is_err() {
        txn.abort();
        return Ok(Err(usage(
            "the Complete record is not a valid EngagementControl entry",
            FIX,
        )));
    }
    let entry = record.clone().seal(Vec::new(), None)?;
    let mut batch = WriteBatch::new(relation::IN_CASE);
    batch.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    batch.add_edge(edge_id(relation::IN_CASE, evid, vid), evid, vid, vec![]);
    batch.compare_and_set_vertex_property(
        vid,
        property::STATE,
        read_state,
        EngagementState::DocumentationComplete.scalar(),
        WriteMismatchPolicy::AbortWrite,
    );
    if let Err(e) = txn.write(db, batch) {
        txn.abort();
        return Err(e.into());
    }
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(DocumentationCompleted {
            engagement: vid,
            completion,
            control_entry: evid,
            recorded_at: seq,
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(fcw(&detail)))
        }
        Err(WriteTxnError::Write(fgdb::WriteError::CompareAndSetMismatch(_))) => Ok(Err(
            completion_refused("the documentation completion was journaled concurrently"),
        )),
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => {
            match db.vertex(evid)? {
                Some(stored) => Ok(recorded_or_conflict(book, &stored, &record)?.map(
                    |recorded_at| DocumentationCompleted {
                        engagement: vid,
                        completion,
                        control_entry: evid,
                        recorded_at,
                        already_recorded: true,
                    },
                )),
                None => Ok(Err(fcw(
                    "the documentation completion was journaled concurrently",
                ))),
            }
        }
        Err(e) => Err(e.into()),
    }
}

fn carry_forward_refused(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::CARRY_FORWARD,
        exit::REFUSAL,
        message.into(),
        "plan §11.12 (audit.sud under both SAB 108 methods with prior-year carry-forward)",
        "carry forward another engagement of this book in the same unit, whose scope periods all end before this one's begin, naming only its uncorrected proposals (`fa engagement sud <prior> --json` lists them)",
    )
}

/// The earliest start and the latest end of `profile`'s scope periods, or
/// `None` when the calendar has no period one of them names.
fn scope_bounds(book: &BookContext, profile: &EngagementProfile) -> Option<(DateDay, DateDay)> {
    let mut bounds: Option<(DateDay, DateDay)> = None;
    for code in &profile.scope_periods {
        let period = crate::policy::calendar_period(book, code)?;
        bounds = Some(match bounds {
            None => (period.start, period.end),
            Some((start, end)) => (start.min(period.start), end.max(period.end)),
        });
    }
    bounds
}

/// Journal `engagement`'s carry-forward of `prior`'s uncorrected
/// misstatements (plan §11.12, SAB 108): one CarryForward record (extension
/// 28) naming the prior engagement and which of its uncorrected proposals
/// turned around through this period's income or an out-of-period
/// correction here corrected. The prior engagement is another of this book,
/// in the same unit, whose scope periods all end by the day this one's
/// first begins; each named ordinal is one of its uncorrected proposals at
/// the head. A later carry-forward governs the summary; every one stays on
/// the record.
#[allow(clippy::too_many_arguments)]
pub async fn carry_forward<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    engagement: &str,
    prior: &str,
    turned_around: Vec<u32>,
    corrected: Vec<u32>,
    req: EngagementRequest,
) -> Outcome<CarriedForward> {
    const FIX: &str = "fa engagement carry-forward <id> --from <prior engagement> [--turned-around N]... [--corrected N]...";
    for code in [engagement, prior] {
        if let Err(why) = check_engagement(code) {
            return Ok(Err(usage(why, FIX)));
        }
    }
    let vid = engagement_vid(book.book_id, engagement);
    let prior_vid = engagement_vid(book.book_id, prior);
    let carried = CarryForward {
        prior: prior_vid,
        turned_around,
        corrected,
    };
    if let Err(why) = carried.check() {
        return Ok(Err(usage(why, FIX)));
    }
    if let Err(r) = admit(db, book, &req.capability, Kind::CarryForward)? {
        return Ok(Err(r));
    }
    if vid == prior_vid {
        return Ok(Err(carry_forward_refused(format!(
            "engagement `{engagement}` cannot carry forward its own misstatements"
        ))));
    }
    let key = record_key(Kind::CarryForward, vid, &req.idempotency_key);
    let evid = entry_vid(book.book_id, &req.capability.holder().0.to_le_bytes(), &key);
    let extension = Some((
        fa_model::entry::ENGAGEMENT_CARRY_FORWARD_EXTENSION,
        carried.canonical_bytes()?,
    ));
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    if let Err(r) = capability_witness(&txn, db, book, &req.capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    let Some((_, profile)) = engagement_row(&txn, db, vid)? else {
        txn.abort();
        return Ok(Err(unknown(engagement)));
    };
    let Some((prior_row, prior_profile)) = engagement_row(&txn, db, prior_vid)? else {
        txn.abort();
        return Ok(Err(unknown(prior)));
    };
    // A point read of the state, as for File: a completion that commits
    // first makes this a first-committer conflict.
    let read_state = txn.vertex_property(db, vid, property::STATE)?;
    let Some(state) = EngagementState::from_scalar(read_state.as_ref()) else {
        txn.abort();
        return Err(KernelError::Corrupt(format!(
            "engagement {:032x} state mirror",
            vid.0
        )));
    };
    if let Some(stored) = txn.vertex(db, evid)? {
        txn.abort();
        let (entry, _) = crate::post::entry_of(&stored)?;
        let stored_state = match &entry.proposal.control {
            Some(ControlPayload::LifecycleTransition { from, .. }) => {
                EngagementState::from_tag(*from)
            }
            _ => None,
        };
        let Some(stored_state) = stored_state else {
            return Ok(Err(conflict_with(&stored)));
        };
        let record = record_proposal(
            book,
            Kind::CarryForward,
            stored_state,
            vid,
            carried.digest()?,
            &req,
            vec![TypedRef::Vertex(prior_vid)],
            0,
            extension,
        );
        return Ok(
            recorded_or_conflict(book, &stored, &record)?.map(|recorded_at| CarriedForward {
                engagement: vid,
                carry_forward: carried,
                control_entry: evid,
                recorded_at,
                added_after_completion: stored_state == EngagementState::DocumentationComplete,
                already_recorded: true,
            }),
        );
    }
    if prior_profile.unit != profile.unit {
        txn.abort();
        return Ok(Err(carry_forward_refused(format!(
            "engagement `{prior}` states its misstatements in unit {}, `{engagement}` in unit {}",
            prior_profile.unit.0, profile.unit.0
        ))));
    }
    match (
        scope_bounds(book, &prior_profile),
        scope_bounds(book, &profile),
    ) {
        (Some((_, prior_end)), Some((start, _))) if prior_end <= start => {}
        (Some(_), Some(_)) => {
            txn.abort();
            return Ok(Err(carry_forward_refused(format!(
                "engagement `{prior}`'s scope periods do not all end before `{engagement}`'s begin"
            ))));
        }
        _ => {
            txn.abort();
            return Err(KernelError::Corrupt(format!(
                "engagement `{prior}` or `{engagement}` names a scope period the calendar does not have"
            )));
        }
    }
    let prior_view = view_of(db, &prior_row)?;
    if let Some(ordinal) = carried
        .turned_around
        .iter()
        .chain(&carried.corrected)
        .find(|ordinal| {
            !prior_view
                .proposals
                .iter()
                .any(|p| p.proposal.ordinal == **ordinal && uncorrected_basis(p).is_some())
        })
    {
        txn.abort();
        return Ok(Err(carry_forward_refused(format!(
            "engagement `{prior}` has no uncorrected proposal {ordinal}"
        ))));
    }
    let record = record_proposal(
        book,
        Kind::CarryForward,
        state,
        vid,
        carried.digest()?,
        &req,
        vec![TypedRef::Vertex(prior_vid)],
        0,
        extension,
    );
    if record.validate().is_err() {
        txn.abort();
        return Ok(Err(usage(
            "the CarryForward record is not a valid EngagementControl entry",
            FIX,
        )));
    }
    let entry = record.clone().seal(Vec::new(), None)?;
    let mut batch = WriteBatch::new(relation::IN_CASE);
    batch.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    batch.add_edge(edge_id(relation::IN_CASE, evid, vid), evid, vid, vec![]);
    if let Err(e) = txn.write(db, batch) {
        txn.abort();
        return Err(e.into());
    }
    let added_after_completion = state == EngagementState::DocumentationComplete;
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(CarriedForward {
            engagement: vid,
            carry_forward: carried,
            control_entry: evid,
            recorded_at: seq,
            added_after_completion,
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(fcw(&detail)))
        }
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => match db.vertex(evid)? {
            Some(stored) => Ok(
                recorded_or_conflict(book, &stored, &record)?.map(|recorded_at| CarriedForward {
                    engagement: vid,
                    carry_forward: carried,
                    control_entry: evid,
                    recorded_at,
                    added_after_completion,
                    already_recorded: true,
                }),
            ),
            None => Ok(Err(fcw("the carry-forward was journaled concurrently"))),
        },
        Err(e) => Err(e.into()),
    }
}

fn differs(engagement: &str, ordinal: u32, why: &str) -> Refusal {
    Refusal::new(
        code::BOOKED_ENTRY_DIFFERS,
        exit::REFUSAL,
        format!("booking engagement `{engagement}` proposal {ordinal} {why}"),
        "plan §11.12 (Booked names the committed entry that makes the proposed correction)",
        format!(
            "book it with the standing trunk entry, recorded after the proposal and effective in its period, that posts exactly its legs (`fa engagement show {engagement} --json` lists them), or pass it with `fa adjustment pass`"
        ),
    )
}

/// The engagement `engagement` and every proposal its records journaled,
/// at the head.
pub fn read_engagement<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    engagement: &str,
) -> Result<Option<EngagementView>, KernelError> {
    let vid = engagement_vid(book.book_id, engagement);
    match db.vertex(vid)? {
        Some(row) if row.labels.contains(&label::ENGAGEMENT) => Ok(Some(view_of(db, &row)?)),
        Some(_) => Err(KernelError::Corrupt(format!(
            "engagement identity {:032x} holds a vertex that is not an Engagement",
            vid.0
        ))),
        None => Ok(None),
    }
}

/// Every engagement of the book, by opening sequence.
pub fn list_engagements<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
) -> Result<Vec<EngagementView>, KernelError> {
    let mut out = Vec::new();
    for row in db.vertices()? {
        if row.labels.contains(&label::ENGAGEMENT) {
            let view = view_of(db, &row)?;
            if view.profile.book_id == book.book_id {
                out.push(view);
            }
        }
    }
    out.sort_by_key(|v| (v.opened_at, v.vid.0));
    Ok(out)
}

/// The `EngagementControl` records with an `IN_CASE` edge to `object`, at
/// `seq`: each record's entry, sequence and transition.
/// One EngagementControl record about an object: its vertex, the entry, the
/// sequence that recorded it, and the transition it journals (from, to).
type Record = (VId, fa_model::Entry, CommitSeq, u8, u8);

fn records_into<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    object: VId,
    seq: CommitSeq,
) -> Result<Vec<Record>, KernelError> {
    let mut out = Vec::new();
    // Only the object's own IN_CASE sources: a view reads its records, never
    // a scan of every edge in the store.
    for source in db.in_neighbours_at(object, relation::IN_CASE, seq)? {
        let Some(src) = db.vertex_at(source, seq)? else {
            continue;
        };
        if !src.labels.contains(&label::ENTRY) {
            continue;
        }
        let (entry, recorded_at) = crate::post::entry_of(&src)?;
        if entry.proposal.class != EntryClass::ENGAGEMENT_CONTROL {
            continue;
        }
        let Some(ControlPayload::LifecycleTransition { from, to, .. }) = &entry.proposal.control
        else {
            return Err(KernelError::Corrupt(format!(
                "engagement record {:032x} carries no LifecycleTransition",
                source.0
            )));
        };
        let (from, to) = (*from, *to);
        out.push((source, entry, recorded_at, from, to));
    }
    out.sort_by_key(|(vid, _, seq, _, _)| (*seq, vid.0));
    Ok(out)
}

/// An engagement as its records state it: the Open record, every Propose
/// record cross-checked against its staged ProposedAdjustment, and each
/// proposal's decision cross-checked against its state mirror.
fn view_of<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    row: &VertexRow,
) -> Result<EngagementView, KernelError> {
    let vid = row.vid;
    let profile = profile_of(row)?;
    if profile.vid() != vid {
        return Err(KernelError::Corrupt(format!(
            "engagement {:032x} carries another engagement's body",
            vid.0
        )));
    }
    let state = EngagementState::from_scalar(prop(row, property::STATE))
        .ok_or_else(|| KernelError::Corrupt(format!("engagement {:032x} state mirror", vid.0)))?;
    let next_proposal = next_of(prop(row, property::ORDINAL), vid)?;
    let seq = db.frontier()?;
    let open = EngagementState::Open.tag();
    let complete = EngagementState::DocumentationComplete.tag();
    let mut opened = None;
    let mut proposals = Vec::new();
    let mut workpapers = Vec::new();
    let mut carry_forwards = Vec::new();
    let mut findings = Vec::new();
    let mut documentation: Option<CompletionView> = None;
    for (record, entry, recorded_at, from, to) in records_into(db, vid, seq)? {
        let Some(ControlPayload::LifecycleTransition {
            object_ref,
            proof_refs,
            ..
        }) = &entry.proposal.control
        else {
            continue;
        };
        if *object_ref != vid {
            continue;
        }
        match (from, to) {
            (0, t) if t == open => opened = Some((recorded_at, entry.proposal.principal_ref)),
            (f, t) if f == open && t == complete => {
                let Some((_, body)) =
                    entry.proposal.extensions.iter().find(|(tag, _)| {
                        *tag == fa_model::entry::DOCUMENTATION_COMPLETION_EXTENSION
                    })
                else {
                    return Err(KernelError::Corrupt(format!(
                        "Complete record {:032x} carries no documentation completion",
                        record.0
                    )));
                };
                if documentation.is_some() {
                    return Err(KernelError::Corrupt(format!(
                        "engagement `{}` completes its documentation twice",
                        profile.engagement
                    )));
                }
                documentation = Some(CompletionView {
                    completion: DocumentationCompletion::decode(body)?,
                    record,
                    recorded_at,
                    completed_by: entry.proposal.principal_ref,
                });
            }
            (f, t)
                if f == t
                    && (f == open || f == complete)
                    && entry.proposal.extensions.is_empty() =>
            {
                let document = match proof_refs.as_slice() {
                    [TypedRef::Object(document)] => document,
                    [TypedRef::Vertex(finding)] => {
                        findings.push(FindingInIndex {
                            finding: *finding,
                            record,
                            filed_at: recorded_at,
                            filed_by: entry.proposal.principal_ref,
                            added_after_completion: f == complete,
                        });
                        continue;
                    }
                    _ => {
                        return Err(KernelError::Corrupt(format!(
                            "File record {:032x} names neither one document nor one finding",
                            record.0
                        )));
                    }
                };
                workpapers.push(WorkpaperView {
                    document: *document,
                    record,
                    filed_at: recorded_at,
                    filed_by: entry.proposal.principal_ref,
                    added_after_completion: f == complete,
                    confirmation: workpaper_confirmation(db, &profile, document)?,
                    representation: workpaper_representation(db, &profile, document)?,
                });
            }
            (f, t)
                if f == t
                    && (f == open || f == complete)
                    && entry.proposal.extensions.iter().any(|(tag, _)| {
                        *tag == fa_model::entry::ENGAGEMENT_CARRY_FORWARD_EXTENSION
                    }) =>
            {
                let [(_, body)] = entry.proposal.extensions.as_slice() else {
                    return Err(KernelError::Corrupt(format!(
                        "CarryForward record {:032x} carries other extensions",
                        record.0
                    )));
                };
                let carry_forward = CarryForward::decode(body)?;
                if proof_refs.as_slice() != [TypedRef::Vertex(carry_forward.prior)] {
                    return Err(KernelError::Corrupt(format!(
                        "CarryForward record {:032x} does not name its prior engagement",
                        record.0
                    )));
                }
                carry_forwards.push(CarryForwardView {
                    carry_forward,
                    record,
                    recorded_at,
                    recorded_by: entry.proposal.principal_ref,
                    added_after_completion: f == complete,
                });
            }
            (f, t) if f == t && (f == open || f == complete) => {
                let Some(proposal) = proposal_record(&entry)? else {
                    return Err(KernelError::Corrupt(format!(
                        "Propose record {:032x} carries no proposed adjustment",
                        record.0
                    )));
                };
                let pvid = proposed_adjustment_vid(
                    profile.book_id,
                    &proposal.engagement,
                    proposal.ordinal,
                );
                let staged = db.vertex_at(pvid, seq)?.ok_or_else(|| {
                    KernelError::Corrupt(format!(
                        "Propose record {:032x} has no ProposedAdjustment vertex",
                        record.0
                    ))
                })?;
                if proposal.engagement != profile.engagement || proposal_of(&staged)? != proposal {
                    return Err(KernelError::Corrupt(format!(
                        "ProposedAdjustment {:032x} disagrees with the Propose record that created it",
                        pvid.0
                    )));
                }
                let state = AdjustmentState::from_scalar(prop(&staged, property::STATE))
                    .ok_or_else(|| {
                        KernelError::Corrupt(format!("proposal {:032x} state mirror", pvid.0))
                    })?;
                let decision = decision_of(db, pvid, seq)?;
                let decided = decision.as_ref().map(|d| d.decision.state());
                if decided.unwrap_or(AdjustmentState::Proposed) != state {
                    return Err(KernelError::Corrupt(format!(
                        "proposal {:032x} state mirror disagrees with its records",
                        pvid.0
                    )));
                }
                proposals.push(ProposalView {
                    vid: pvid,
                    proposal,
                    record,
                    proposed_at: recorded_at,
                    proposed_by: entry.proposal.principal_ref,
                    state,
                    decision,
                    added_after_completion: f == complete,
                });
            }
            _ => {
                return Err(KernelError::Corrupt(format!(
                    "engagement record {:032x} names transition {from} -> {to}",
                    record.0
                )));
            }
        }
    }
    let (opened_at, opened_by) = opened.ok_or_else(|| {
        KernelError::Corrupt(format!("engagement {:032x} has no Open record", vid.0))
    })?;
    // The state mirror, each record's own states and the journal order agree:
    // a record journaled after the completion says so, and none before it.
    let completed_at = documentation.as_ref().map(|c| c.recorded_at);
    if (state == EngagementState::DocumentationComplete) != completed_at.is_some()
        || proposals
            .iter()
            .map(|p| (p.proposed_at, p.added_after_completion))
            .chain(
                workpapers
                    .iter()
                    .map(|w| (w.filed_at, w.added_after_completion)),
            )
            .chain(
                carry_forwards
                    .iter()
                    .map(|c: &CarryForwardView| (c.recorded_at, c.added_after_completion)),
            )
            .chain(
                findings
                    .iter()
                    .map(|f: &FindingInIndex| (f.filed_at, f.added_after_completion)),
            )
            .any(|(at, after)| completed_at.is_some_and(|c| at > c) != after)
    {
        return Err(KernelError::Corrupt(format!(
            "engagement `{}`: its documentation completion disagrees with its records",
            profile.engagement
        )));
    }
    for proposal in &mut proposals {
        if let (Some(decision), Some(c)) = (proposal.decision.as_mut(), completed_at) {
            decision.added_after_completion = decision.recorded_at > c;
        }
    }
    proposals.sort_by_key(|p| p.proposal.ordinal);
    if proposals
        .iter()
        .enumerate()
        .any(|(i, p)| usize::try_from(p.proposal.ordinal).ok() != Some(i + 1))
        || usize::try_from(next_proposal).ok() != Some(proposals.len() + 1)
    {
        return Err(KernelError::Corrupt(format!(
            "engagement `{}`: its proposals are not numbered 1..{next_proposal}",
            profile.engagement
        )));
    }
    Ok(EngagementView {
        vid,
        profile,
        state,
        opened_at,
        opened_by,
        next_proposal,
        proposals,
        workpapers,
        documentation,
        carry_forwards,
        findings,
    })
}

/// The Confirmed attestation over `document`, judged for this engagement.
fn workpaper_confirmation<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    profile: &EngagementProfile,
    document: &Oid,
) -> Result<Option<WorkpaperConfirmation>, KernelError> {
    let vid = crate::attestation::confirmed_vid(profile.book_id, document);
    let Some((stored, _)) = crate::attestation::read_attestation(db, vid)? else {
        return Ok(None);
    };
    let crate::attestation::AttestationClaim::Confirmed {
        by_party,
        balance,
        as_of,
    } = stored.attestation.claim
    else {
        return Err(KernelError::Corrupt(format!(
            "confirmation identity {:032x} holds a {} attestation",
            vid.0,
            stored.attestation.claim.name()
        )));
    };
    let received_by = crate::attestation::confirmation_received_by(db, document)?;
    Ok(Some(WorkpaperConfirmation {
        attestation: vid,
        by_party,
        balance,
        as_of,
        attested_by: stored.attestation.principal,
        received_by,
        audit_grade: received_by == Some(profile.firm_principal),
    }))
}

/// The Represented attestation over `document`, if any.
fn workpaper_representation<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    profile: &EngagementProfile,
    document: &Oid,
) -> Result<Option<WorkpaperRepresentation>, KernelError> {
    let vid = crate::attestation::represented_vid(profile.book_id, document);
    let Some((stored, _)) = crate::attestation::read_attestation(db, vid)? else {
        return Ok(None);
    };
    let crate::attestation::AttestationClaim::Represented { claims, as_of } =
        stored.attestation.claim
    else {
        return Err(KernelError::Corrupt(format!(
            "representation identity {:032x} holds a {} attestation",
            vid.0,
            stored.attestation.claim.name()
        )));
    };
    Ok(Some(WorkpaperRepresentation {
        attestation: vid,
        claims: claims.len(),
        as_of,
        attested_by: stored.attestation.principal,
    }))
}

/// A proposal's one decision, if any; two decisions are corruption.
fn decision_of<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    pvid: VId,
    seq: CommitSeq,
) -> Result<Option<RecordedDecision>, KernelError> {
    let proposed = AdjustmentState::Proposed.tag();
    let mut decided = None;
    for (record, entry, recorded_at, from, to) in records_into(db, pvid, seq)? {
        let Some(ControlPayload::LifecycleTransition {
            object_ref,
            proof_refs,
            reason_code,
            ..
        }) = &entry.proposal.control
        else {
            continue;
        };
        if *object_ref != pvid {
            continue;
        }
        let decision = match (from, to, proof_refs.as_slice()) {
            (f, t, [TypedRef::Vertex(entry)])
                if f == proposed && t == AdjustmentState::Booked.tag() =>
            {
                AdjustmentDecision::Book { entry: *entry }
            }
            (f, t, []) if f == proposed && t == AdjustmentState::Passed.tag() => {
                AdjustmentDecision::Pass {
                    reason_code: *reason_code,
                }
            }
            _ => {
                return Err(KernelError::Corrupt(format!(
                    "proposal record {:032x} names transition {from} -> {to}",
                    record.0
                )));
            }
        };
        if decided.is_some() {
            return Err(KernelError::Corrupt(format!(
                "proposal {:032x} is decided twice",
                pvid.0
            )));
        }
        let superseded_by = match decision {
            AdjustmentDecision::Book { entry } => superseder_at(db, entry, seq)?,
            AdjustmentDecision::Pass { .. } => None,
        };
        decided = Some(RecordedDecision {
            decision,
            record,
            recorded_at,
            decided_by: entry.proposal.principal_ref,
            superseded_by,
            // Set by the engagement's view, which knows its completion.
            added_after_completion: false,
        });
    }
    Ok(decided)
}

/// The entry that reversed or replaced `entry` at `seq`, if any. Only a
/// reversal or a replacement supersedes, each at an identity derived from
/// its target (plan §4.9), so two point reads decide it.
pub fn superseder_at<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    entry: VId,
    seq: CommitSeq,
) -> Result<Option<VId>, KernelError> {
    for identity in [
        crate::rows::reversal_vid(entry),
        crate::rows::replacement_vid(entry),
    ] {
        if let Some(row) = db.vertex_at(identity, seq)?
            && row.labels.contains(&label::ENTRY)
        {
            return Ok(Some(row.vid));
        }
    }
    Ok(None)
}

/// A correction's effect on the statements, in one unit: what booking it
/// would change. A positive `income` raises net income; `assets` is debits
/// less credits on asset accounts, `liabilities` and `equity` credits less
/// debits on theirs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StatementEffect {
    pub income: i128,
    pub assets: i128,
    pub liabilities: i128,
    pub equity: i128,
}

impl StatementEffect {
    fn add(self, other: Self) -> Result<Self, KernelError> {
        let sum = |a: i128, b: i128| {
            a.checked_add(b)
                .ok_or_else(|| KernelError::Corrupt("uncorrected misstatements overflow".into()))
        };
        Ok(Self {
            income: sum(self.income, other.income)?,
            assets: sum(self.assets, other.assets)?,
            liabilities: sum(self.liabilities, other.liabilities)?,
            equity: sum(self.equity, other.equity)?,
        })
    }

    /// The largest absolute effect on any line.
    #[must_use]
    pub fn largest(self) -> u128 {
        [self.income, self.assets, self.liabilities, self.equity]
            .into_iter()
            .map(i128::unsigned_abs)
            .max()
            .unwrap_or(0)
    }
}

/// Why a proposal is an uncorrected misstatement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Uncorrected {
    /// Passed, for its registered `adjustment_pass` reason.
    Passed { reason_code: u16 },
    /// Booked, but the booked entry has since been reversed or replaced
    /// (`by`), so the correction no longer stands.
    Superseded { entry: VId, by: VId },
}

/// One uncorrected proposal in the summary of uncorrected misstatements.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UncorrectedItem {
    pub ordinal: u32,
    pub effective_date: DateDay,
    pub basis: Uncorrected,
    /// Its effect in the engagement's unit.
    pub effect: StatementEffect,
    /// Every line's effect is at most the stated clearly trivial threshold.
    pub clearly_trivial: bool,
    /// Units of its legs other than the engagement's: listed, never converted.
    pub other_units: Vec<UnitId>,
}

/// A standing out-of-period correction in an engagement's scope (plan §8.2):
/// an `Adjusting` entry effective in a scope period that carries
/// `fa:prior-period-error:v1`, so it corrects an earlier period's error in
/// this period's income. Read from the journal by the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutOfPeriodCorrection {
    pub entry: VId,
    pub effective_date: DateDay,
    /// The earlier period whose error it corrects.
    pub relates_to: PeriodRef,
    pub legs: Vec<ProposalLeg>,
}

/// One out-of-period correction in the summary of uncorrected misstatements.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutOfPeriodItem {
    pub entry: VId,
    pub effective_date: DateDay,
    pub relates_to: PeriodRef,
    /// What moving the correction out of this period's income would change,
    /// in the engagement's unit: its income effect reversed, against opening
    /// retained earnings in `equity`.
    pub effect: StatementEffect,
    /// Every line's effect is at most the stated clearly trivial threshold.
    pub clearly_trivial: bool,
    /// Units of its legs other than the engagement's: listed, never converted.
    pub other_units: Vec<UnitId>,
}

/// What became of a prior engagement's uncorrected misstatement in this
/// period, as the latest carry-forward states it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Carried {
    /// Still uncorrected at this period's end: the iron curtain counts it.
    Uncorrected,
    /// Reversed through this period's income: the rollover counts it.
    TurnedAround,
    /// Corrected in this period by an out-of-period correction, which the
    /// summary counts itself: neither method counts the item again.
    Corrected,
}

impl Carried {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Uncorrected => "Uncorrected",
            Self::TurnedAround => "TurnedAround",
            Self::Corrected => "Corrected",
        }
    }
}

/// A prior engagement's uncorrected misstatement carried into this summary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CarriedItem {
    /// Its number in the prior engagement.
    pub prior_ordinal: u32,
    pub effective_date: DateDay,
    pub carried: Carried,
    /// What correcting it would change now, in the engagement's unit: for an
    /// uncorrected item, the period-end balance sheet (its prior income is
    /// in opening retained earnings by now); for a turned-around item, this
    /// period's income against opening retained earnings; nothing for a
    /// corrected one.
    pub effect: StatementEffect,
    pub clearly_trivial: bool,
    pub other_units: Vec<UnitId>,
}

/// The summary of uncorrected misstatements (plan §11.12, `audit.sud`):
/// the effect of every passed proposal, and of every booked one whose entry
/// has since been reversed or replaced, had it been booked and stood, in
/// the engagement's unit, and mechanical comparisons with the stated
/// parameters, under both SAB 108 methods. The proposals count under both;
/// an out-of-period correction misstates this period's income (rollover)
/// but leaves the period-end balance sheet corrected, so the iron curtain
/// does not count it. With a carry-forward, a prior engagement's
/// uncorrected misstatements count too: those still uncorrected under the
/// iron curtain, those that turned around under the rollover.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UncorrectedSummary {
    pub unit: UnitId,
    pub items: Vec<UncorrectedItem>,
    pub out_of_period: Vec<OutOfPeriodItem>,
    /// The prior engagement the latest carry-forward names.
    pub carried_from: Option<VId>,
    pub carried: Vec<CarriedItem>,
    /// Rollover: the uncorrected proposals', the out-of-period corrections'
    /// and the turned-around carried items' effect on the period's income.
    pub rollover_income: i128,
    /// Iron curtain: the uncorrected proposals' and the still-uncorrected
    /// carried items' cumulative effect at period end.
    pub iron_curtain: StatementEffect,
    /// Under either method, the largest absolute total exceeds the stated
    /// performance materiality.
    pub exceeds_performance: bool,
    /// Under either method, the largest absolute total exceeds the stated
    /// overall materiality.
    pub exceeds_overall: bool,
}

/// Why `p` is an uncorrected misstatement, if it is one: passed, or booked
/// with an entry since reversed or replaced.
fn uncorrected_basis(p: &ProposalView) -> Option<Uncorrected> {
    match &p.decision {
        Some(RecordedDecision {
            decision: AdjustmentDecision::Pass { reason_code },
            ..
        }) => Some(Uncorrected::Passed {
            reason_code: *reason_code,
        }),
        Some(RecordedDecision {
            decision: AdjustmentDecision::Book { entry },
            superseded_by: Some(by),
            ..
        }) => Some(Uncorrected::Superseded {
            entry: *entry,
            by: *by,
        }),
        _ => None,
    }
}

/// The effect of booking `legs`, in `unit`, and the other units they name.
fn effect_of(
    legs: &[ProposalLeg],
    unit: UnitId,
    account_type: &impl Fn(VId) -> Option<fa_model::AccountType>,
    what: &dyn Fn() -> String,
) -> Result<(StatementEffect, Vec<UnitId>), KernelError> {
    use fa_model::AccountType;
    let mut effect = StatementEffect::default();
    let mut other_units = Vec::new();
    for leg in legs {
        if leg.amount.unit != unit {
            if !other_units.contains(&leg.amount.unit) {
                other_units.push(leg.amount.unit);
            }
            continue;
        }
        let ty = account_type(leg.account).ok_or_else(|| {
            KernelError::Corrupt(format!(
                "{} names account {:032x}, which the chart does not have",
                what(),
                leg.account.0
            ))
        })?;
        // A debit raises an asset; a credit raises a liability, equity
        // or income. Amounts are positive, so both signs are exact.
        let negated = leg
            .amount
            .mantissa
            .checked_neg()
            .ok_or_else(|| KernelError::Corrupt("leg amount overflow".into()))?;
        let (debit_less_credit, credit_less_debit) = match leg.side {
            Side::Debit => (leg.amount.mantissa, negated),
            Side::Credit => (negated, leg.amount.mantissa),
        };
        let line = match ty {
            AccountType::ASSET => StatementEffect {
                assets: debit_less_credit,
                ..StatementEffect::default()
            },
            AccountType::LIABILITY => StatementEffect {
                liabilities: credit_less_debit,
                ..StatementEffect::default()
            },
            AccountType::EQUITY => StatementEffect {
                equity: credit_less_debit,
                ..StatementEffect::default()
            },
            AccountType::REVENUE | AccountType::EXPENSE => StatementEffect {
                income: credit_less_debit,
                ..StatementEffect::default()
            },
            _ => continue,
        };
        effect = effect.add(line)?;
    }
    other_units.sort();
    Ok((effect, other_units))
}

/// The summary of uncorrected misstatements for `view`'s uncorrected
/// proposals, the out-of-period `corrections` in its scope and, when it
/// carries one forward, the `prior` engagement's summary (its own items;
/// its carry-forward is not chained). `account_type` names each leg
/// account's type (from the chart); memo legs are outside the statements
/// and are not summarized.
pub fn uncorrected_misstatements(
    view: &EngagementView,
    corrections: &[OutOfPeriodCorrection],
    prior: Option<&UncorrectedSummary>,
    account_type: impl Fn(VId) -> Option<fa_model::AccountType>,
) -> Result<UncorrectedSummary, KernelError> {
    let unit = view.profile.unit;
    let trivial = view.profile.materiality.clearly_trivial.unsigned_abs();
    let mut items = Vec::new();
    let mut total = StatementEffect::default();
    for p in &view.proposals {
        let Some(basis) = uncorrected_basis(p) else {
            continue;
        };
        let ordinal = p.proposal.ordinal;
        let (effect, other_units) = effect_of(&p.proposal.legs, unit, &account_type, &|| {
            format!("proposal {ordinal}")
        })?;
        total = total.add(effect)?;
        items.push(UncorrectedItem {
            ordinal,
            effective_date: p.proposal.effective_date,
            basis,
            effect,
            clearly_trivial: effect.largest() <= trivial,
            other_units,
        });
    }
    let mut rollover_income = total.income;
    let mut out_of_period = Vec::new();
    for c in corrections {
        let (booked, other_units) = effect_of(&c.legs, unit, &account_type, &|| {
            format!("out-of-period entry {:032x}", c.entry.0)
        })?;
        // The correction put `booked.income` into this period's income; the
        // misstatement is undone by taking it back out, against opening
        // retained earnings.
        let reversed = booked
            .income
            .checked_neg()
            .ok_or_else(|| KernelError::Corrupt("out-of-period income overflow".into()))?;
        let effect = StatementEffect {
            income: reversed,
            equity: booked.income,
            ..StatementEffect::default()
        };
        rollover_income = rollover_income
            .checked_add(reversed)
            .ok_or_else(|| KernelError::Corrupt("uncorrected misstatements overflow".into()))?;
        out_of_period.push(OutOfPeriodItem {
            entry: c.entry,
            effective_date: c.effective_date,
            relates_to: c.relates_to.clone(),
            effect,
            clearly_trivial: effect.largest() <= trivial,
            other_units,
        });
    }
    let overflow = || KernelError::Corrupt("uncorrected misstatements overflow".into());
    let carry_forward = view.carry_forwards.last().map(|c| &c.carry_forward);
    let mut carried = Vec::new();
    match (carry_forward, prior) {
        (None, _) => {}
        (Some(_), None) => {
            return Err(KernelError::Corrupt(format!(
                "engagement `{}` carries a prior engagement forward, but its summary was not supplied",
                view.profile.engagement
            )));
        }
        (Some(_), Some(prior)) if prior.unit != unit => {
            return Err(KernelError::Corrupt(format!(
                "engagement `{}` carries forward a summary in another unit",
                view.profile.engagement
            )));
        }
        (Some(carry_forward), Some(prior)) => {
            for item in &prior.items {
                let e = item.effect;
                let ordinal = item.ordinal;
                let disposition = if carry_forward.turned_around.binary_search(&ordinal).is_ok() {
                    Carried::TurnedAround
                } else if carry_forward.corrected.binary_search(&ordinal).is_ok() {
                    Carried::Corrected
                } else {
                    Carried::Uncorrected
                };
                let effect = match disposition {
                    // At this period's end the prior period's income effect
                    // sits in opening retained earnings.
                    Carried::Uncorrected => StatementEffect {
                        income: 0,
                        assets: e.assets,
                        liabilities: e.liabilities,
                        equity: e.equity.checked_add(e.income).ok_or_else(overflow)?,
                    },
                    // The reversal went through this period's income; taking
                    // it back out moves it to opening retained earnings.
                    Carried::TurnedAround => StatementEffect {
                        income: e.income.checked_neg().ok_or_else(overflow)?,
                        equity: e.income,
                        ..StatementEffect::default()
                    },
                    Carried::Corrected => StatementEffect::default(),
                };
                match disposition {
                    Carried::Uncorrected => total = total.add(effect)?,
                    Carried::TurnedAround => {
                        rollover_income = rollover_income
                            .checked_add(effect.income)
                            .ok_or_else(overflow)?;
                    }
                    Carried::Corrected => {}
                }
                carried.push(CarriedItem {
                    prior_ordinal: ordinal,
                    effective_date: item.effective_date,
                    carried: disposition,
                    effect,
                    clearly_trivial: effect.largest() <= trivial,
                    other_units: item.other_units.clone(),
                });
            }
        }
    }
    let m = view.profile.materiality;
    let largest = total.largest().max(rollover_income.unsigned_abs());
    Ok(UncorrectedSummary {
        unit,
        items,
        out_of_period,
        carried_from: carry_forward.map(|c| c.prior),
        carried,
        rollover_income,
        iron_curtain: total,
        exceeds_performance: largest > m.performance.unsigned_abs(),
        exceeds_overall: largest > m.overall.unsigned_abs(),
    })
}

// ---------------------------------------------------------------------------
// Out-of-period corrections (plan §8.2: "Immaterial errors corrected in the
// current period without a case are `Adjusting` entries with `reason_code:
// PriorPeriodError { relates_to: PeriodRef }`")
// ---------------------------------------------------------------------------

const PRIOR_PERIOD_ERROR_VERSION: u16 = 1;

/// The `fa:prior-period-error:v1` bytes naming `relates_to`.
fn prior_period_error_bytes(relates_to: &PeriodRef) -> Result<Vec<u8>, KernelError> {
    let mut w = Writer::with_capacity(6 + relates_to.calendar.len() + relates_to.code.len());
    w.u16(PRIOR_PERIOD_ERROR_VERSION);
    relates_to.encode(&mut w);
    Ok(w.finish()?)
}

/// The earlier period whose error an entry corrects
/// (`fa:prior-period-error:v1`): `Ok(None)` without the extension, `Err(why)`
/// when its bytes are malformed.
pub fn prior_period_error(p: &EntryPayload) -> Result<Option<PeriodRef>, String> {
    let Some((_, raw)) = p
        .extensions
        .iter()
        .find(|(t, _)| *t == PRIOR_PERIOD_ERROR_EXTENSION)
    else {
        return Ok(None);
    };
    let malformed = |e: fa_model::DecodeError| format!("fa:prior-period-error:v1: {e:?}");
    let mut r = Reader::new(raw);
    let version = r.u16("prior_period_error.version").map_err(malformed)?;
    if version != PRIOR_PERIOD_ERROR_VERSION {
        return Err(format!(
            "fa:prior-period-error:v1 version {version} is not supported"
        ));
    }
    let relates_to = PeriodRef::decode(&mut r).map_err(malformed)?;
    r.finish().map_err(malformed)?;
    Ok(Some(relates_to))
}

/// `p` marked as correcting the error of the earlier period `relates_to`
/// (extensions stay sorted by tag).
pub fn with_prior_period_error(
    mut p: EntryPayload,
    relates_to: &PeriodRef,
) -> Result<EntryPayload, KernelError> {
    p.schema_minor = p.schema_minor.max(fa_model::entry::EXTENSIONS_MINOR);
    p.extensions
        .retain(|(t, _)| *t != PRIOR_PERIOD_ERROR_EXTENSION);
    p.extensions.push((
        PRIOR_PERIOD_ERROR_EXTENSION,
        prior_period_error_bytes(relates_to)?,
    ));
    p.extensions.sort_by_key(|(t, _)| *t);
    Ok(p)
}

/// Judge a submitted proposal's prior-period-error marker before the posting
/// transaction (plan §8.2): `Ok(None)` when it carries none. Only an
/// `Adjusting` entry carries it, and it names a period of this book's
/// calendar that ends on or before the entry's effective date.
pub(crate) fn admit_prior_period_error(
    book: &BookContext,
    p: &EntryPayload,
) -> Result<Option<PeriodRef>, Refusal> {
    let refuse = |why: String| {
        Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            why,
            "plan §8.2 (an immaterial prior-period error corrected in the current period without a case is an Adjusting entry naming the period it relates to)",
            "post the correction as class Adjusting with prior_period_error naming an earlier period of this book's calendar, or open a case (`fa case open`) for a restatement",
        )
    };
    let relates_to = match prior_period_error(p) {
        Ok(None) => return Ok(None),
        Ok(Some(r)) => r,
        Err(why) => return Err(refuse(why)),
    };
    if p.class != EntryClass::ADJUSTING {
        return Err(refuse(format!(
            "only an Adjusting entry corrects a prior-period error; this is a {}",
            p.class.name().unwrap_or("?")
        )));
    }
    if relates_to.calendar != book.calendar.id {
        return Err(refuse(format!(
            "prior_period_error names calendar `{}`, not this book's `{}`",
            relates_to.calendar, book.calendar.id
        )));
    }
    let Some(period) = crate::policy::calendar_period(book, &relates_to.code) else {
        return Err(refuse(format!(
            "prior_period_error names `{}`, which is no period of calendar `{}`",
            relates_to.code, book.calendar.id
        )));
    };
    // `end` is exclusive: the period is earlier when it ends by this day.
    if period.end > p.effective_date {
        return Err(refuse(format!(
            "prior_period_error names `{}`, which does not end before the correction's effective date {}",
            relates_to.code,
            p.effective_date.render()
        )));
    }
    Ok(Some(relates_to))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usd() -> UnitId {
        UnitId(1)
    }

    fn leg(side: Side, account: u128, mantissa: i128) -> ProposalLeg {
        ProposalLeg {
            side,
            account: VId(account),
            amount: Amount::new(usd(), mantissa),
        }
    }

    fn profile() -> EngagementProfile {
        EngagementProfile {
            book_id: Id128([7; 16]),
            engagement: "FY2026 audit".into(),
            kind: EngagementKind::Audit,
            firm_principal: VId(9),
            scope_periods: vec!["FY2026-P01".into(), "FY2026-P02".into()],
            unit: usd(),
            materiality: Materiality {
                overall: 5_000_000,
                performance: 3_750_000,
                clearly_trivial: 250_000,
            },
            report_release_day: Some(DateDay(20_600)),
            capability_commitment: [3; 32],
        }
    }

    #[test]
    fn profiles_and_proposals_round_trip_and_refuse_bad_domains() {
        let p = profile();
        assert_eq!(
            EngagementProfile::decode(&p.canonical_bytes().unwrap()).unwrap(),
            p
        );
        let proposal = ProposedAdjustment {
            engagement: p.engagement.clone(),
            ordinal: 1,
            effective_date: DateDay(20_500),
            legs: vec![leg(Side::Debit, 1, 1_000), leg(Side::Credit, 2, 1_000)],
        };
        assert_eq!(
            ProposedAdjustment::decode(&proposal.canonical_bytes().unwrap()).unwrap(),
            proposal
        );
        for bad in [
            Materiality {
                overall: 0,
                ..p.materiality
            },
            Materiality {
                performance: 6_000_000,
                ..p.materiality
            },
            Materiality {
                clearly_trivial: 4_000_000,
                ..p.materiality
            },
            Materiality {
                clearly_trivial: -1,
                ..p.materiality
            },
        ] {
            let q = EngagementProfile {
                materiality: bad,
                ..p.clone()
            };
            assert!(q.check().is_err(), "{bad:?}");
            assert!(EngagementProfile::decode(&q.canonical_bytes().unwrap()).is_err());
        }
        for periods in [
            Vec::new(),
            vec!["FY2026-P02".to_string(), "FY2026-P01".to_string()],
            vec!["FY2026-P01".to_string(), "FY2026-P01".to_string()],
        ] {
            let q = EngagementProfile {
                scope_periods: periods,
                ..p.clone()
            };
            assert!(q.check().is_err());
        }
        let mut truncated = p.canonical_bytes().unwrap();
        truncated.pop();
        assert!(EngagementProfile::decode(&truncated).is_err());
    }

    #[test]
    fn proposals_balance_per_unit_with_positive_legs() {
        assert!(check_legs(&[leg(Side::Debit, 1, 5), leg(Side::Credit, 2, 5)]).is_ok());
        assert!(
            check_legs(&[
                leg(Side::Debit, 1, 5),
                leg(Side::Credit, 2, 3),
                leg(Side::Credit, 3, 2)
            ])
            .is_ok()
        );
        for legs in [
            vec![leg(Side::Debit, 1, 5)],
            vec![leg(Side::Debit, 1, 5), leg(Side::Credit, 2, 4)],
            vec![leg(Side::Debit, 1, 0), leg(Side::Credit, 2, 0)],
            vec![leg(Side::Debit, 1, -5), leg(Side::Credit, 2, -5)],
            vec![
                leg(Side::Debit, 1, i128::MAX),
                leg(Side::Debit, 2, i128::MAX),
                leg(Side::Credit, 3, 1),
            ],
        ] {
            assert!(check_legs(&legs).is_err(), "{legs:?}");
        }
        // Two units each balance on their own.
        let eur = UnitId(2);
        assert!(
            check_legs(&[
                leg(Side::Debit, 1, 5),
                leg(Side::Credit, 2, 5),
                ProposalLeg {
                    side: Side::Debit,
                    account: VId(3),
                    amount: Amount::new(eur, 7)
                },
                ProposalLeg {
                    side: Side::Credit,
                    account: VId(4),
                    amount: Amount::new(eur, 6)
                },
            ])
            .is_err()
        );
    }

    #[test]
    fn kinds_and_states_have_stable_tags() {
        for kind in EngagementKind::ALL {
            assert_eq!(EngagementKind::from_tag(kind.tag()), Some(kind));
            assert_eq!(EngagementKind::from_name(kind.name()), Some(kind));
        }
        assert_eq!(EngagementKind::from_tag(0), None);
        let open = EngagementState::Open;
        let complete = EngagementState::DocumentationComplete;
        assert_eq!(Kind::Open.states(open), (0, 1));
        assert_eq!(Kind::Propose.states(open), (1, 1));
        assert_eq!(Kind::Book.states(open), (1, 2));
        assert_eq!(Kind::Pass.states(open), (1, 3));
        assert_eq!(Kind::File.states(open), (1, 1));
        assert_eq!(Kind::CarryForward.states(open), (1, 1));
        assert_eq!(Kind::Complete.states(open), (1, 2));
        // After completion, Propose, File and CarryForward keep the
        // completed state, so their records say they are additions after
        // completion.
        assert_eq!(Kind::Propose.states(complete), (2, 2));
        assert_eq!(Kind::File.states(complete), (2, 2));
        assert_eq!(Kind::CarryForward.states(complete), (2, 2));
        assert_eq!(Kind::Complete.states(complete), (1, 2));
        for state in [open, complete] {
            assert_eq!(EngagementState::from_tag(state.tag()), Some(state));
            assert_eq!(
                EngagementState::from_scalar(Some(&state.scalar())),
                Some(state)
            );
        }
        assert_eq!(EngagementState::from_tag(0), None);
        assert_eq!(EngagementState::from_tag(3), None);
    }

    /// AS 1215.15: the completion date lies within 45 days after the report
    /// release date, inclusive; before it or one day late is refused. The
    /// encoding round-trips and a decoded body is checked again.
    #[test]
    fn documentation_completes_within_45_days_after_the_report_release() {
        let release = DateDay(20_600);
        let on = |days: i32| DocumentationCompletion {
            report_release_day: release,
            completion_day: DateDay(release.0 + days),
        };
        for days in [0, 1, 44, 45] {
            assert!(on(days).check().is_ok(), "{days}");
            let bytes = on(days).canonical_bytes().unwrap();
            assert_eq!(DocumentationCompletion::decode(&bytes).unwrap(), on(days));
        }
        for days in [-1, 46, 365] {
            assert!(on(days).check().is_err(), "{days}");
            let bytes = on(days).canonical_bytes().unwrap();
            assert!(DocumentationCompletion::decode(&bytes).is_err(), "{days}");
        }
        let extreme = DocumentationCompletion {
            report_release_day: DateDay(i32::MIN),
            completion_day: DateDay(i32::MAX),
        };
        assert!(
            extreme.check().is_err(),
            "overflow is refused, never wrapped"
        );
        assert_ne!(on(1).digest().unwrap(), on(2).digest().unwrap());
    }

    fn proposal_view(ordinal: u32, legs: Vec<ProposalLeg>) -> ProposalView {
        ProposalView {
            vid: VId(100 + u128::from(ordinal)),
            proposal: ProposedAdjustment {
                engagement: "FY2026 audit".into(),
                ordinal,
                effective_date: DateDay(20_500),
                legs,
            },
            record: VId(200 + u128::from(ordinal)),
            proposed_at: CommitSeq(3),
            proposed_by: VId(9),
            state: AdjustmentState::Proposed,
            decision: None,
            added_after_completion: false,
        }
    }

    fn decided(mut p: ProposalView, decision: AdjustmentDecision) -> ProposalView {
        p.state = decision.state();
        p.decision = Some(RecordedDecision {
            decision,
            record: VId(300),
            recorded_at: CommitSeq(4),
            decided_by: VId(9),
            superseded_by: None,
            added_after_completion: false,
        });
        p
    }

    /// A booking whose entry was later reversed by `by`.
    fn superseded(p: ProposalView, entry: VId, by: VId) -> ProposalView {
        let mut p = decided(p, AdjustmentDecision::Book { entry });
        if let Some(d) = p.decision.as_mut() {
            d.superseded_by = Some(by);
        }
        p
    }

    fn engagement_view(proposals: Vec<ProposalView>) -> EngagementView {
        EngagementView {
            vid: VId(50),
            profile: profile(),
            state: EngagementState::Open,
            opened_at: CommitSeq(2),
            opened_by: VId(9),
            next_proposal: u32::try_from(proposals.len()).unwrap() + 1,
            proposals,
            workpapers: Vec::new(),
            documentation: None,
            carry_forwards: Vec::new(),
            findings: Vec::new(),
        }
    }

    /// Cash 1 (asset), accrued 2 (liability), revenue 4, expense 5.
    fn chart(account: VId) -> Option<fa_model::AccountType> {
        use fa_model::AccountType;
        match account.0 {
            1 => Some(AccountType::ASSET),
            2 => Some(AccountType::LIABILITY),
            3 => Some(AccountType::EQUITY),
            4 => Some(AccountType::REVENUE),
            5 => Some(AccountType::EXPENSE),
            _ => None,
        }
    }

    /// Passed corrections, and booked ones whose entry was since reversed,
    /// never a standing booking or an undecided proposal; each line in its
    /// own sign (equity included), other units listed and never converted,
    /// and the totals compared mechanically
    /// with the stated parameters (performance 37,500.00, overall
    /// 50,000.00, clearly trivial 2,500.00).
    #[test]
    fn the_summary_sums_passed_corrections_by_line_against_the_stated_parameters() {
        let pass = |reason_code| AdjustmentDecision::Pass { reason_code };
        let eur = UnitId(2);
        let view = engagement_view(vec![
            // Unrecorded fees: expense up 40.00, accrued liabilities up 40.00.
            decided(
                proposal_view(
                    1,
                    vec![leg(Side::Debit, 5, 4_000), leg(Side::Credit, 2, 4_000)],
                ),
                pass(3),
            ),
            // Booked: not an uncorrected misstatement.
            decided(
                proposal_view(
                    2,
                    vec![
                        leg(Side::Debit, 1, 9_999_999),
                        leg(Side::Credit, 4, 9_999_999),
                    ],
                ),
                AdjustmentDecision::Book { entry: VId(77) },
            ),
            // Unrecorded revenue with a EUR leg pair beside it.
            decided(
                proposal_view(
                    3,
                    vec![
                        leg(Side::Debit, 1, 100),
                        leg(Side::Credit, 4, 100),
                        ProposalLeg {
                            side: Side::Debit,
                            account: VId(1),
                            amount: Amount::new(eur, 7),
                        },
                        ProposalLeg {
                            side: Side::Credit,
                            account: VId(4),
                            amount: Amount::new(eur, 7),
                        },
                    ],
                ),
                pass(1),
            ),
            // Still proposed: not summarized.
            proposal_view(4, vec![leg(Side::Debit, 5, 1), leg(Side::Credit, 2, 1)]),
            // A declared dividend booked to equity, then the booking entry
            // reversed: uncorrected again (equity down 20.00, liabilities
            // up 20.00).
            superseded(
                proposal_view(
                    5,
                    vec![leg(Side::Debit, 3, 2_000), leg(Side::Credit, 2, 2_000)],
                ),
                VId(78),
                VId(79),
            ),
        ]);
        let summary = uncorrected_misstatements(&view, &[], None, chart).unwrap();
        assert_eq!(summary.unit, usd());
        assert_eq!(
            summary
                .items
                .iter()
                .map(|i| (i.ordinal, i.basis))
                .collect::<Vec<_>>(),
            [
                (1, Uncorrected::Passed { reason_code: 3 }),
                (3, Uncorrected::Passed { reason_code: 1 }),
                (
                    5,
                    Uncorrected::Superseded {
                        entry: VId(78),
                        by: VId(79)
                    }
                ),
            ]
        );
        assert_eq!(
            summary.items[0].effect,
            StatementEffect {
                income: -4_000,
                liabilities: 4_000,
                ..StatementEffect::default()
            }
        );
        assert_eq!(
            summary.items[1].effect,
            StatementEffect {
                income: 100,
                assets: 100,
                ..StatementEffect::default()
            }
        );
        assert_eq!(summary.items[1].other_units, [eur]);
        assert_eq!(
            summary.items[2].effect,
            StatementEffect {
                liabilities: 2_000,
                equity: -2_000,
                ..StatementEffect::default()
            }
        );
        assert!(summary.items.iter().all(|i| i.clearly_trivial));
        assert_eq!(summary.rollover_income, -3_900);
        assert_eq!(
            summary.iron_curtain,
            StatementEffect {
                income: -3_900,
                assets: 100,
                liabilities: 6_000,
                equity: -2_000
            }
        );
        assert!(!summary.exceeds_performance && !summary.exceeds_overall);

        // Above performance (37,500.00) but not overall (50,000.00), then
        // above both; neither is clearly trivial.
        for (amount, performance, overall) in [(4_000_000, true, false), (6_000_000, true, true)] {
            let view = engagement_view(vec![decided(
                proposal_view(
                    1,
                    vec![leg(Side::Debit, 5, amount), leg(Side::Credit, 2, amount)],
                ),
                pass(3),
            )]);
            let summary = uncorrected_misstatements(&view, &[], None, chart).unwrap();
            assert_eq!(summary.exceeds_performance, performance, "{amount}");
            assert_eq!(summary.exceeds_overall, overall, "{amount}");
            assert!(!summary.items[0].clearly_trivial);
        }

        // A leg on an account the chart does not have is corruption.
        let view = engagement_view(vec![decided(
            proposal_view(1, vec![leg(Side::Debit, 99, 5), leg(Side::Credit, 2, 5)]),
            pass(4),
        )]);
        assert!(uncorrected_misstatements(&view, &[], None, chart).is_err());
    }

    /// SAB 108: an out-of-period correction misstates this period's income,
    /// so the rollover counts it, reversed against opening retained
    /// earnings; it corrects the period-end balance sheet, so the iron
    /// curtain does not. Materiality is judged under either method.
    #[test]
    fn out_of_period_corrections_count_under_the_rollover_method_only() {
        let view = engagement_view(vec![decided(
            proposal_view(
                1,
                vec![leg(Side::Debit, 5, 4_000), leg(Side::Credit, 2, 4_000)],
            ),
            AdjustmentDecision::Pass { reason_code: 3 },
        )]);
        // Last year's unrecorded fees, 30,000.00, expensed this year.
        let correction = OutOfPeriodCorrection {
            entry: VId(90),
            effective_date: DateDay(20_550),
            relates_to: PeriodRef {
                calendar: "fiscal".into(),
                code: "FY2025-P12".into(),
            },
            legs: vec![
                leg(Side::Debit, 5, 3_000_000),
                leg(Side::Credit, 2, 3_000_000),
            ],
        };
        let summary =
            uncorrected_misstatements(&view, std::slice::from_ref(&correction), None, chart)
                .unwrap();
        let [item] = summary.out_of_period.as_slice() else {
            panic!("one out-of-period item: {:?}", summary.out_of_period)
        };
        assert_eq!(item.entry, VId(90));
        assert_eq!(item.relates_to, correction.relates_to);
        assert_eq!(
            item.effect,
            StatementEffect {
                income: 3_000_000,
                equity: -3_000_000,
                ..StatementEffect::default()
            },
            "income understated by the expense; opening retained earnings overstated"
        );
        assert!(!item.clearly_trivial);
        assert_eq!(summary.rollover_income, 3_000_000 - 4_000);
        assert_eq!(
            summary.iron_curtain,
            StatementEffect {
                income: -4_000,
                liabilities: 4_000,
                ..StatementEffect::default()
            },
            "the corrected balance sheet carries only the passed proposal"
        );
        assert!(!summary.exceeds_performance && !summary.exceeds_overall);

        // 39,960.00 under rollover is above performance (37,500.00) though
        // the iron curtain total (40.00) is not.
        let mut larger = correction;
        larger.legs = vec![
            leg(Side::Debit, 5, 4_000_000),
            leg(Side::Credit, 2, 4_000_000),
        ];
        let summary = uncorrected_misstatements(&view, &[larger], None, chart).unwrap();
        assert_eq!(summary.rollover_income, 3_996_000);
        assert_eq!(summary.iron_curtain.largest(), 4_000);
        assert!(summary.exceeds_performance && !summary.exceeds_overall);
    }

    /// SAB 108 carry-forward: a prior engagement's item still uncorrected
    /// counts at this period's end under the iron curtain, its prior income
    /// now in opening retained earnings; a turned-around one counts in this
    /// period's income under the rollover; a corrected one counts under
    /// neither, since its out-of-period correction is counted itself. The
    /// latest carry-forward governs.
    #[test]
    fn a_carry_forward_counts_each_prior_item_under_the_method_its_fate_decides() {
        // The prior engagement passed three fee accruals: 10.00, 20.00, 40.00.
        let accrual = |ordinal, amount| {
            decided(
                proposal_view(
                    ordinal,
                    vec![leg(Side::Debit, 5, amount), leg(Side::Credit, 2, amount)],
                ),
                AdjustmentDecision::Pass { reason_code: 3 },
            )
        };
        let prior_view = engagement_view(vec![
            accrual(1, 1_000),
            accrual(2, 2_000),
            accrual(3, 4_000),
        ]);
        let prior = uncorrected_misstatements(&prior_view, &[], None, chart).unwrap();
        let carry = |record: u128, turned_around: Vec<u32>, corrected: Vec<u32>| CarryForwardView {
            carry_forward: CarryForward {
                prior: VId(51),
                turned_around,
                corrected,
            },
            record: VId(record),
            recorded_at: CommitSeq(9),
            recorded_by: VId(9),
            added_after_completion: false,
        };
        let mut view = engagement_view(Vec::new());
        view.carry_forwards.push(carry(400, vec![2], vec![3]));
        assert!(
            uncorrected_misstatements(&view, &[], None, chart).is_err(),
            "a carry-forward without the prior summary"
        );
        let summary = uncorrected_misstatements(&view, &[], Some(&prior), chart).unwrap();
        assert_eq!(summary.carried_from, Some(VId(51)));
        assert_eq!(
            summary
                .carried
                .iter()
                .map(|c| (c.prior_ordinal, c.carried, c.effect))
                .collect::<Vec<_>>(),
            [
                (
                    1,
                    Carried::Uncorrected,
                    StatementEffect {
                        liabilities: 1_000,
                        equity: -1_000,
                        ..StatementEffect::default()
                    }
                ),
                (
                    2,
                    Carried::TurnedAround,
                    StatementEffect {
                        income: 2_000,
                        equity: -2_000,
                        ..StatementEffect::default()
                    }
                ),
                (3, Carried::Corrected, StatementEffect::default()),
            ]
        );
        assert_eq!(summary.rollover_income, 2_000);
        assert_eq!(
            summary.iron_curtain,
            StatementEffect {
                liabilities: 1_000,
                equity: -1_000,
                ..StatementEffect::default()
            }
        );

        // A later carry-forward states that nothing turned around or was
        // corrected: every prior item is uncorrected at this period's end.
        view.carry_forwards.push(carry(401, Vec::new(), Vec::new()));
        let summary = uncorrected_misstatements(&view, &[], Some(&prior), chart).unwrap();
        assert_eq!(summary.rollover_income, 0);
        assert_eq!(
            summary.iron_curtain,
            StatementEffect {
                liabilities: 7_000,
                equity: -7_000,
                ..StatementEffect::default()
            }
        );
    }

    #[test]
    fn a_carry_forward_round_trips_and_refuses_unordered_or_overlapping_ordinals() {
        let carried = CarryForward {
            prior: VId(51),
            turned_around: vec![1, 4],
            corrected: vec![2],
        };
        assert_eq!(
            CarryForward::decode(&carried.canonical_bytes().unwrap()).unwrap(),
            carried
        );
        for (turned_around, corrected) in [
            (vec![4, 1], Vec::new()),
            (vec![1, 1], Vec::new()),
            (vec![0], Vec::new()),
            (vec![2], vec![2]),
        ] {
            let bad = CarryForward {
                prior: VId(51),
                turned_around,
                corrected,
            };
            assert!(bad.check().is_err(), "{bad:?}");
            assert!(CarryForward::decode(&bad.canonical_bytes().unwrap()).is_err());
        }
        let fewer = CarryForward {
            corrected: Vec::new(),
            ..carried.clone()
        };
        assert_ne!(carried.digest().unwrap(), fewer.digest().unwrap());
    }
}
