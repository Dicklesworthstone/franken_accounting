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
//!   `next_proposal = 1`.
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
//!
//! A decided proposal is never decided again (FA-REF-181): its state mirror
//! moves by compare-and-set, so two concurrent decisions cannot both commit.
//! Every record is a trunk record under the op `sod_policy.toml` registers
//! for its EngagementControl transition (`produce`), so an Agent prepares
//! none. Nothing here alters a committed amount.

use std::collections::BTreeMap;

use fa_model::symbols::{label, property, relation};
use fa_model::{
    ControlKind, ControlPayload, EntryClass, EntryOrigin, EntryPayload, Erasable, Id128, Reader,
    TypedRef, Writer, domain_digest, engagement_vid, entry_mirrors, entry_vid, period_vid,
    proposed_adjustment_vid,
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
const PROFILE_DOMAIN: &[u8] = b"fa:engagement:v1";
const PROPOSAL_DOMAIN: &[u8] = b"fa:proposed-adjustment:v1";
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

/// An `Engagement`'s `state` projection. One state in this build; completing
/// documentation is added as a new transition, never by reusing this tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngagementState {
    Open,
}

impl EngagementState {
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            Self::Open => 1,
        }
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Open => "open",
        }
    }

    fn scalar(self) -> CanonicalScalar {
        CanonicalScalar::Int(i64::from(self.tag()))
    }

    fn from_scalar(v: Option<&CanonicalScalar>) -> Option<Self> {
        match v {
            Some(CanonicalScalar::Int(1)) => Some(Self::Open),
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
}

#[derive(Clone, Copy)]
enum Kind {
    Open,
    Propose,
    Book,
    Pass,
}

impl Kind {
    fn transition(self) -> &'static str {
        match self {
            Self::Open => "Open",
            Self::Propose => "Propose",
            Self::Book => "Book",
            Self::Pass => "Pass",
        }
    }

    fn tag(self) -> u8 {
        match self {
            Self::Open => 0,
            Self::Propose => 1,
            Self::Book => 2,
            Self::Pass => 3,
        }
    }

    /// `(from, to)` on the record's object: the Engagement for Open and
    /// Propose, the ProposedAdjustment for Book and Pass.
    fn states(self) -> (u8, u8) {
        let open = EngagementState::Open.tag();
        let proposed = AdjustmentState::Proposed.tag();
        match self {
            Self::Open => (0, open),
            Self::Propose => (open, open),
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

#[allow(clippy::too_many_arguments)]
fn record_proposal(
    book: &BookContext,
    kind: Kind,
    object: VId,
    spec_digest: [u8; 32],
    req: &EngagementRequest,
    proof_refs: Vec<TypedRef>,
    reason_code: u16,
    extension: Option<(u16, Vec<u8>)>,
) -> EntryPayload {
    let (from, to) = kind.states();
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
/// `Engagement` vertex with its immutable profile, `state = Open` and
/// `next_proposal = 1`, and the record's `IN_CASE` edge to it. Every scope
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
                exit::REFUSAL,
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
        (property::NEXT_PROPOSAL, CanonicalScalar::Int(1)),
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
    if EngagementState::from_scalar(txn.vertex_property(db, vid, property::STATE)?.as_ref())
        != Some(EngagementState::Open)
    {
        txn.abort();
        return Err(KernelError::Corrupt(format!(
            "engagement {:032x} state mirror",
            vid.0
        )));
    }
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
    let read_next = txn.vertex_property(db, vid, property::NEXT_PROPOSAL)?;
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
        property::NEXT_PROPOSAL,
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
    let candidate = record_proposal(
        book,
        Kind::Propose,
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
                exit::REFUSAL,
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
    if engagement_row(&txn, db, vid)?.is_none() {
        txn.abort();
        return Ok(Err(unknown(engagement)));
    }
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
    let record = record_proposal(
        book,
        kind,
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
        let (booked, _) = crate::post::entry_of(&row)?;
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
        // One committed entry makes one correction: it books no other
        // proposal of the engagement. Each other proposal's state is a
        // point-read witness, so a concurrent booking of the same entry
        // conflicts at commit (first committer wins).
        let next = next_of(
            txn.vertex_property(db, vid, property::NEXT_PROPOSAL)?
                .as_ref(),
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

fn differs(engagement: &str, ordinal: u32, why: &str) -> Refusal {
    Refusal::new(
        code::BOOKED_ENTRY_DIFFERS,
        exit::REFUSAL,
        format!("booking engagement `{engagement}` proposal {ordinal} {why}"),
        "plan §11.12 (Booked names the committed entry that makes the proposed correction)",
        format!(
            "book it with the committed trunk entry that posts exactly its legs (`fa engagement show {engagement} --json` lists them), or pass it with `fa adjustment pass`"
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
fn records_into<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    object: VId,
    seq: CommitSeq,
) -> Result<Vec<(VId, fa_model::Entry, CommitSeq, u8, u8)>, KernelError> {
    let mut out = Vec::new();
    for edge in db.edges_at(seq)? {
        let e = &edge.entry;
        if e.dst != object
            || e.relation != relation::IN_CASE
            || e.eid != edge_id(relation::IN_CASE, e.src, object)
        {
            continue;
        }
        let Some(src) = db.vertex_at(e.src, seq)? else {
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
                e.src.0
            )));
        };
        let (from, to) = (*from, *to);
        out.push((e.src, entry, recorded_at, from, to));
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
    let next_proposal = next_of(prop(row, property::NEXT_PROPOSAL), vid)?;
    let seq = db.frontier()?;
    let open = EngagementState::Open.tag();
    let mut opened = None;
    let mut proposals = Vec::new();
    for (record, entry, recorded_at, from, to) in records_into(db, vid, seq)? {
        let Some(ControlPayload::LifecycleTransition { object_ref, .. }) = &entry.proposal.control
        else {
            continue;
        };
        if *object_ref != vid {
            continue;
        }
        match (from, to) {
            (0, t) if t == open => opened = Some((recorded_at, entry.proposal.principal_ref)),
            (f, t) if f == open && t == open => {
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
    })
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
        decided = Some(RecordedDecision {
            decision,
            record,
            recorded_at,
            decided_by: entry.proposal.principal_ref,
        });
    }
    Ok(decided)
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

/// One passed proposal in the summary of uncorrected misstatements.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UncorrectedItem {
    pub ordinal: u32,
    pub effective_date: DateDay,
    pub reason_code: u16,
    /// Its effect in the engagement's unit.
    pub effect: StatementEffect,
    /// Every line's effect is at most the stated clearly trivial threshold.
    pub clearly_trivial: bool,
    /// Units of its legs other than the engagement's: listed, never converted.
    pub other_units: Vec<UnitId>,
}

/// The summary of uncorrected misstatements (plan §11.12, `audit.sud`):
/// every passed proposal's effect had it been booked, in the engagement's
/// unit, and mechanical comparisons with the stated parameters. With no
/// prior-period engagement linked there is no carry-forward, so the rollover
/// (current-period income) and iron-curtain (period-end balance sheet)
/// quantifications sum the same items; both are reported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UncorrectedSummary {
    pub unit: UnitId,
    pub items: Vec<UncorrectedItem>,
    /// Rollover: the passed items' effect on the period's income.
    pub rollover_income: i128,
    /// Iron curtain: the passed items' cumulative effect at period end.
    pub iron_curtain: StatementEffect,
    /// The largest absolute total exceeds the stated performance materiality.
    pub exceeds_performance: bool,
    /// The largest absolute total exceeds the stated overall materiality.
    pub exceeds_overall: bool,
}

/// The summary of uncorrected misstatements for `view`'s passed proposals.
/// `account_type` names each leg account's type (from the chart); memo legs
/// are outside the statements and are not summarized.
pub fn uncorrected_misstatements(
    view: &EngagementView,
    account_type: impl Fn(VId) -> Option<fa_model::AccountType>,
) -> Result<UncorrectedSummary, KernelError> {
    use fa_model::AccountType;
    let unit = view.profile.unit;
    let mut items = Vec::new();
    let mut total = StatementEffect::default();
    for p in &view.proposals {
        let Some(RecordedDecision {
            decision: AdjustmentDecision::Pass { reason_code },
            ..
        }) = &p.decision
        else {
            continue;
        };
        let reason_code = *reason_code;
        let mut effect = StatementEffect::default();
        let mut other_units = Vec::new();
        for leg in &p.proposal.legs {
            if leg.amount.unit != unit {
                if !other_units.contains(&leg.amount.unit) {
                    other_units.push(leg.amount.unit);
                }
                continue;
            }
            let ty = account_type(leg.account).ok_or_else(|| {
                KernelError::Corrupt(format!(
                    "proposal {} names account {:032x}, which the chart does not have",
                    p.proposal.ordinal, leg.account.0
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
        total = total.add(effect)?;
        items.push(UncorrectedItem {
            ordinal: p.proposal.ordinal,
            effective_date: p.proposal.effective_date,
            reason_code,
            effect,
            clearly_trivial: effect.largest()
                <= view.profile.materiality.clearly_trivial.unsigned_abs(),
            other_units,
        });
    }
    let m = view.profile.materiality;
    Ok(UncorrectedSummary {
        unit,
        items,
        rollover_income: total.income,
        iron_curtain: total,
        exceeds_performance: total.largest() > m.performance.unsigned_abs(),
        exceeds_overall: total.largest() > m.overall.unsigned_abs(),
    })
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
        assert_eq!(Kind::Open.states(), (0, 1));
        assert_eq!(Kind::Propose.states(), (1, 1));
        assert_eq!(Kind::Book.states(), (1, 2));
        assert_eq!(Kind::Pass.states(), (1, 3));
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
        }
    }

    fn decided(mut p: ProposalView, decision: AdjustmentDecision) -> ProposalView {
        p.state = decision.state();
        p.decision = Some(RecordedDecision {
            decision,
            record: VId(300),
            recorded_at: CommitSeq(4),
            decided_by: VId(9),
        });
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
        }
    }

    /// Cash 1 (asset), accrued 2 (liability), revenue 4, expense 5.
    fn chart(account: VId) -> Option<fa_model::AccountType> {
        use fa_model::AccountType;
        match account.0 {
            1 => Some(AccountType::ASSET),
            2 => Some(AccountType::LIABILITY),
            4 => Some(AccountType::REVENUE),
            5 => Some(AccountType::EXPENSE),
            _ => None,
        }
    }

    /// Passed corrections only, each line in its own sign, other units
    /// listed and never converted, and the totals compared mechanically
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
        ]);
        let summary = uncorrected_misstatements(&view, chart).unwrap();
        assert_eq!(summary.unit, usd());
        assert_eq!(
            summary
                .items
                .iter()
                .map(|i| (i.ordinal, i.reason_code))
                .collect::<Vec<_>>(),
            [(1, 3), (3, 1)]
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
        assert!(summary.items.iter().all(|i| i.clearly_trivial));
        assert_eq!(summary.rollover_income, -3_900);
        assert_eq!(
            summary.iron_curtain,
            StatementEffect {
                income: -3_900,
                assets: 100,
                liabilities: 4_000,
                equity: 0
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
            let summary = uncorrected_misstatements(&view, chart).unwrap();
            assert_eq!(summary.exceeds_performance, performance, "{amount}");
            assert_eq!(summary.exceeds_overall, overall, "{amount}");
            assert!(!summary.items[0].clearly_trivial);
        }

        // A leg on an account the chart does not have is corruption.
        let view = engagement_view(vec![decided(
            proposal_view(1, vec![leg(Side::Debit, 99, 5), leg(Side::Credit, 2, 5)]),
            pass(4),
        )]);
        assert!(uncorrected_misstatements(&view, chart).is_err());
    }
}
