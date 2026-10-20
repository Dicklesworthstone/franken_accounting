//! Restatement cases (plan §8.3, Appendix A `RestatementCase`, Appendix B
//! `OpenRestatementCase` … `DiscloseCase`; bead fa-75j4).
//!
//! A `RestatementCase` is the control object that makes a material
//! correction legal in a `Closed` or `Locked` period. Its life cycle is
//! `Proposed → Determined → Rehearsed → Approved → Posted → Disclosed →
//! Closed`, each step a `CaseControl` record (class 30, control kind 17), a
//! `LifecycleTransition` on the case's `RestatementCase` vertex at
//! [`fa_model::restatement_case_vid`]`(book, ordinal)`:
//!
//! - **Open** (`0 → Proposed`, or `0 → Determined` when the determination is
//!   already made) journals the immutable case body in extension 19
//!   `fa:restatement-case:v1`: its kind, the periods it affects, the
//!   optional narrative document, and the determination when given at open.
//!   Cases are numbered from 1 in commit order.
//! - **Determine** (`Proposed → Determined`) journals the determination in
//!   extension 20 `fa:case-determination:v1`: the day the non-reliance
//!   determination was made and the document that records its authority.
//!   For a `Restatement` the Item 4.02 Form 8-K clock starts that day, so the
//!   date is a journaled fact rather than a later reconstruction.
//! - **Rehearse** (`Determined → Rehearsed`) journals the rehearsal in
//!   extension 21 `fa:case-rehearsal:v1`: the scenario the correction was
//!   rehearsed on, the digest of its diff certificate (retained in this
//!   book, replayed by the facade before this record), the trunk sequence it
//!   forked at and the periods the diff covers, which must include every
//!   period the case affects. The scenario must still be open.
//!
//! The narrative and authority documents are the records' proof refs and
//! must be verified documents of this book; every affected period must
//! exist. The vertex's `state` moves by compare-and-set, so two concurrent
//! transitions of one case race and the first committer wins.
//!
//! **Authority.** Every record is a trunk record under `restate`
//! (`sod_policy.toml` `case-open`, `case-determine`, `case-rehearse`); an
//! Agent prepares none. Dual-control approval of the case's effect manifest,
//! posting, disclosure and closing are later slices of fa-75j4: until they
//! land, a case cannot leave `Rehearsed`, and Revision, Restatement and
//! PriorPeriodAdjustment entries stay refused.

use fa_model::limits::{MAX_BATCH_ENTRIES, MAX_PERIOD_REF_BYTES};
use fa_model::symbols::{label, property, relation};
use fa_model::{
    ControlKind, ControlPayload, EntryClass, EntryOrigin, EntryPayload, Erasable, Id128, Oid,
    Reader, TypedRef, Writer, domain_digest, entry_mirrors, entry_vid, period_vid,
    report_certificate_vid, restatement_case_vid, scenario_vid,
};
use fa_policy::{Capability, Intent};
use fa_registry::evidence_policy::EvidencePolicy;
use fa_time::DateDay;
use fgdb::{Database, VertexRow, WriteBatch, WriteMismatchPolicy, WriteTxn, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::evidence::{document_vid, drift, hex, verify_row};
use crate::genesis::BookContext;
use crate::policy::{capability_witness, refusal as denial, steward};
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{bytes, edge_id, prop, scalar_bytes};

/// Canonical bytes of a case body (extension 19): `u16 version ‖
/// book_id[16] ‖ u32 ordinal ‖ u8 kind ‖ list(str period) ‖ opt oid
/// narrative ‖ opt (i32 day ‖ oid authority)`.
pub const CASE_VERSION: u16 = 1;
/// Canonical bytes of a determination (extension 20): `u16 version ‖ i32
/// day ‖ oid authority`.
pub const DETERMINATION_VERSION: u16 = 1;
/// Canonical bytes of a rehearsal (extension 21): `u16 version ‖ str
/// scenario ‖ [32] certificate ‖ u64 fork_at ‖ list(str period) ‖
/// list(u128 plan record)`.
pub const REHEARSAL_VERSION: u16 = 1;
/// The periods one case may affect.
pub const MAX_CASE_PERIODS: usize = 64;
const BODY_DOMAIN: &[u8] = b"fa:restatement-case:v1";
const DETERMINATION_DOMAIN: &[u8] = b"fa:case-determination:v1";
const REHEARSAL_DOMAIN: &[u8] = b"fa:case-rehearsal:v1";
const RECORD_KEY_DOMAIN: &[u8] = b"fa:case-record-key:v1";

/// What a case corrects (plan §8.3 `RestatementCase.kind`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CaseKind {
    /// An immaterial prior-period correction ("little r").
    Revision,
    /// A material prior-period correction ("Big R", ASC 250 / IAS 8).
    Restatement,
    /// A correction posted in the current period against opening equity.
    PriorPeriodAdjustment,
    /// The retrospective application of a policy change to comparatives.
    PolicyChangeRetrospective,
}

impl CaseKind {
    pub const ALL: [Self; 4] = [
        Self::Revision,
        Self::Restatement,
        Self::PriorPeriodAdjustment,
        Self::PolicyChangeRetrospective,
    ];

    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Revision => 1,
            Self::Restatement => 2,
            Self::PriorPeriodAdjustment => 3,
            Self::PolicyChangeRetrospective => 4,
        }
    }

    #[must_use]
    pub fn from_tag(tag: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.tag() == tag)
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Revision => "Revision",
            Self::Restatement => "Restatement",
            Self::PriorPeriodAdjustment => "PriorPeriodAdjustment",
            Self::PolicyChangeRetrospective => "PolicyChangeRetrospective",
        }
    }

    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.name() == name)
    }
}

/// A case's place in its life cycle (plan §8.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CaseState {
    Proposed,
    Determined,
    Rehearsed,
    Approved,
    Posted,
    Disclosed,
    Closed,
}

impl CaseState {
    pub const ALL: [Self; 7] = [
        Self::Proposed,
        Self::Determined,
        Self::Rehearsed,
        Self::Approved,
        Self::Posted,
        Self::Disclosed,
        Self::Closed,
    ];

    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Proposed => 1,
            Self::Determined => 2,
            Self::Rehearsed => 3,
            Self::Approved => 4,
            Self::Posted => 5,
            Self::Disclosed => 6,
            Self::Closed => 7,
        }
    }

    #[must_use]
    pub fn from_tag(tag: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.tag() == tag)
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Proposed => "Proposed",
            Self::Determined => "Determined",
            Self::Rehearsed => "Rehearsed",
            Self::Approved => "Approved",
            Self::Posted => "Posted",
            Self::Disclosed => "Disclosed",
            Self::Closed => "Closed",
        }
    }

    fn scalar(self) -> CanonicalScalar {
        CanonicalScalar::Int(i64::from(self.tag()))
    }

    fn from_scalar(value: Option<&CanonicalScalar>) -> Option<Self> {
        match value {
            Some(CanonicalScalar::Int(n)) => u8::try_from(*n).ok().and_then(Self::from_tag),
            _ => None,
        }
    }
}

/// The non-reliance (or immateriality) determination: the day it was made
/// and the document recording the authority that made it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Determination {
    pub day: DateDay,
    pub authority: Oid,
}

impl Determination {
    fn write(&self, w: &mut Writer) {
        w.i32(self.day.0).fixed(&self.authority.0);
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, fa_model::DecodeError> {
        Ok(Self {
            day: DateDay(r.i32("case.determination.day")?),
            authority: Oid(r.fixed("case.determination.authority")?),
        })
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, KernelError> {
        let mut w = Writer::with_capacity(40);
        w.u16(DETERMINATION_VERSION);
        self.write(&mut w);
        Ok(w.finish()?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, KernelError> {
        let mut r = Reader::new(bytes);
        if r.u16("case.determination.version").map_err(decode)? != DETERMINATION_VERSION {
            return Err(KernelError::Corrupt(
                "unsupported case determination version".into(),
            ));
        }
        let determination = Self::read(&mut r).map_err(decode)?;
        r.finish().map_err(decode)?;
        Ok(determination)
    }
}

/// A case's rehearsal: the scenario the correction ran on and the diff
/// certificate that compares it with trunk as reported, retained in the book
/// under its digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rehearsal {
    pub scenario: String,
    /// The retained certificate's digest (its
    /// [`fa_model::report_certificate_vid`] locator).
    pub certificate: [u8; 32],
    /// The trunk sequence the scenario forked at, which the certificate's
    /// trunk side is certified at.
    pub fork_at: CommitSeq,
    /// The periods the diff covers, sorted and distinct.
    pub periods: Vec<String>,
    /// The scenario's Plan records the diff covers, in planning order: a
    /// prefix of the scenario's intents, and the entries the case will post.
    pub intents: Vec<VId>,
}

impl Rehearsal {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, KernelError> {
        let mut w = Writer::with_capacity(64 + self.scenario.len() + self.periods.len() * 16);
        w.u16(REHEARSAL_VERSION)
            .str(&self.scenario)
            .fixed(&self.certificate)
            .u64(self.fork_at.0)
            .list(&self.periods, |w, p| {
                w.str(p);
            })
            .list(&self.intents, |w, v| {
                w.u128(v.0);
            });
        Ok(w.finish()?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, KernelError> {
        let mut r = Reader::new(bytes);
        if r.u16("case.rehearsal.version").map_err(decode)? != REHEARSAL_VERSION {
            return Err(KernelError::Corrupt(
                "unsupported case rehearsal version".into(),
            ));
        }
        let scenario = r
            .str(
                crate::scenario::MAX_SCENARIO_NAME_BYTES,
                "case.rehearsal.scenario",
            )
            .map_err(decode)?
            .to_string();
        let certificate = r.fixed("case.rehearsal.certificate").map_err(decode)?;
        let fork_at = CommitSeq(r.u64("case.rehearsal.fork_at").map_err(decode)?);
        let periods = r
            .list(MAX_CASE_PERIODS, "case.rehearsal.periods", |r| {
                Ok(r.str(MAX_PERIOD_REF_BYTES, "case.rehearsal.period")?
                    .to_string())
            })
            .map_err(decode)?;
        let intents = r
            .list(MAX_BATCH_ENTRIES, "case.rehearsal.intents", |r| {
                Ok(VId(r.u128("case.rehearsal.intent")?))
            })
            .map_err(decode)?;
        r.finish().map_err(decode)?;
        let rehearsal = Self {
            scenario,
            certificate,
            fork_at,
            periods,
            intents,
        };
        rehearsal
            .check()
            .map_err(|why| KernelError::Corrupt(format!("case rehearsal: {why}")))?;
        Ok(rehearsal)
    }

    /// The field domains a rehearsal must satisfy, as one sentence.
    pub fn check(&self) -> Result<(), String> {
        let max_name = crate::scenario::MAX_SCENARIO_NAME_BYTES;
        if self.scenario.is_empty() || self.scenario.len() > max_name {
            return Err(format!("a scenario name is 1..={max_name} bytes"));
        }
        if self.intents.len() > MAX_BATCH_ENTRIES {
            return Err(format!(
                "a rehearsal covers at most {MAX_BATCH_ENTRIES} intents"
            ));
        }
        if self
            .intents
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != self.intents.len()
        {
            return Err("a rehearsal names each Plan record once".into());
        }
        if self.periods.is_empty() || self.periods.len() > MAX_CASE_PERIODS {
            return Err(format!(
                "a rehearsal's diff covers 1..={MAX_CASE_PERIODS} periods; this one names {}",
                self.periods.len()
            ));
        }
        if !self.periods.windows(2).all(|w| w[0] < w[1]) {
            return Err("a rehearsal's periods are sorted and distinct".into());
        }
        Ok(())
    }
}

/// A case's immutable body, fixed when it is opened (Appendix A
/// `RestatementCase` body). Approvals bind the effect manifest an `Approved`
/// record names, never fields of this body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaseBody {
    pub book_id: Id128,
    /// Its place among the book's cases, from 1, in commit order.
    pub ordinal: u32,
    pub kind: CaseKind,
    /// The periods the case affects, sorted and distinct.
    pub periods: Vec<String>,
    pub narrative: Option<Oid>,
    /// The determination, when it was already made at open.
    pub determination: Option<Determination>,
}

impl CaseBody {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, KernelError> {
        let mut w = Writer::with_capacity(96 + self.periods.len() * 16);
        w.u16(CASE_VERSION)
            .fixed(&self.book_id.0)
            .u32(self.ordinal)
            .u8(self.kind.tag())
            .list(&self.periods, |w, p| {
                w.str(p);
            })
            .opt(self.narrative.as_ref(), |w, oid| {
                w.fixed(&oid.0);
            })
            .opt(self.determination.as_ref(), |w, d| d.write(w));
        Ok(w.finish()?)
    }

    /// Decode and validate a body; refuses an unknown version, a field out of
    /// its domain, and trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, KernelError> {
        let mut r = Reader::new(bytes);
        if r.u16("case.version").map_err(decode)? != CASE_VERSION {
            return Err(KernelError::Corrupt(
                "unsupported restatement case version".into(),
            ));
        }
        let book_id = Id128(r.fixed("case.book_id").map_err(decode)?);
        let ordinal = r.u32("case.ordinal").map_err(decode)?;
        let tag = r.u8("case.kind").map_err(decode)?;
        let kind = CaseKind::from_tag(tag)
            .ok_or_else(|| KernelError::Corrupt(format!("restatement case kind tag {tag}")))?;
        let periods = r
            .list(MAX_CASE_PERIODS, "case.periods", |r| {
                Ok(r.str(MAX_PERIOD_REF_BYTES, "case.period")?.to_string())
            })
            .map_err(decode)?;
        let narrative = r
            .opt("case.narrative", |r| Ok(Oid(r.fixed("case.narrative")?)))
            .map_err(decode)?;
        let determination = r
            .opt("case.determination", Determination::read)
            .map_err(decode)?;
        r.finish().map_err(decode)?;
        let body = Self {
            book_id,
            ordinal,
            kind,
            periods,
            narrative,
            determination,
        };
        body.check()
            .map_err(|why| KernelError::Corrupt(format!("restatement case: {why}")))?;
        Ok(body)
    }

    /// The field domains a body must satisfy, as one sentence.
    pub fn check(&self) -> Result<(), String> {
        if self.ordinal == 0 {
            return Err("case ordinals start at 1".into());
        }
        if self.periods.is_empty() || self.periods.len() > MAX_CASE_PERIODS {
            return Err(format!(
                "a case affects 1..={MAX_CASE_PERIODS} periods; this one names {}",
                self.periods.len()
            ));
        }
        if let Some(bad) = self
            .periods
            .iter()
            .find(|p| p.is_empty() || p.len() > MAX_PERIOD_REF_BYTES)
        {
            return Err(format!(
                "a period code is 1..={MAX_PERIOD_REF_BYTES} bytes; `{bad}` is not"
            ));
        }
        if !self.periods.windows(2).all(|w| w[0] < w[1]) {
            return Err("a case's periods are sorted and distinct".into());
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<[u8; 32], KernelError> {
        Ok(domain_digest(BODY_DOMAIN, &[&self.canonical_bytes()?]))
    }

    #[must_use]
    pub fn vid(&self) -> VId {
        restatement_case_vid(self.book_id, self.ordinal)
    }
}

fn decode(e: fa_model::DecodeError) -> KernelError {
    KernelError::Model(e.into())
}

/// A record's author, date, description and key.
#[derive(Clone, Debug)]
pub struct CaseRequest {
    pub capability: Capability,
    pub effective_date: DateDay,
    pub description: Erasable<String>,
    pub idempotency_key: Vec<u8>,
}

/// One journaled transition of a case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaseTransition {
    pub from: Option<CaseState>,
    pub to: CaseState,
    pub control_entry: VId,
    pub recorded_at: CommitSeq,
    pub principal: VId,
}

/// A case as its body, its `state` mirror and its records state it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaseView {
    pub vid: VId,
    pub body: CaseBody,
    pub state: CaseState,
    /// The determination, from the body or from the Determine record.
    pub determination: Option<Determination>,
    /// The rehearsal, from the Rehearse record.
    pub rehearsal: Option<Rehearsal>,
    /// Every transition, in commit order; the first is the Open record.
    pub transitions: Vec<CaseTransition>,
}

/// A recorded transition and the case after it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaseRecorded {
    pub case: CaseView,
    pub control_entry: VId,
    pub recorded_at: CommitSeq,
    pub already_recorded: bool,
}

#[derive(Clone, Copy)]
enum Act {
    Open,
    Determine,
    Rehearse,
}

impl Act {
    fn transition(self) -> &'static str {
        match self {
            Self::Open => "Open",
            Self::Determine => "Determine",
            Self::Rehearse => "Rehearse",
        }
    }

    fn tag(self) -> u8 {
        match self {
            Self::Open => 0,
            Self::Determine => 1,
            Self::Rehearse => 2,
        }
    }
}

fn usage(message: impl Into<String>, fix: &str) -> Refusal {
    Refusal::new(
        code::STRUCTURE,
        exit::USAGE,
        message.into(),
        "plan §8.3, Appendix A RestatementCase (bead fa-75j4)",
        fix,
    )
}

fn unknown(ordinal: u32) -> Refusal {
    Refusal::new(
        code::CASE_UNKNOWN,
        exit::REFUSAL,
        format!("this book has no restatement case {ordinal}"),
        "plan §8.3 (a RestatementCase is opened with OpenRestatementCase)",
        "list the book's cases with `fa case list --json`, or open one with `fa case open --kind Restatement --periods <code>`",
    )
}

fn wrong_state(ordinal: u32, state: CaseState, act: &str, admitted: &str) -> Refusal {
    Refusal::new(
        code::CASE_STATE,
        exit::REFUSAL,
        format!(
            "restatement case {ordinal} is {}; {act} applies only to a case that is {admitted}",
            state.name()
        ),
        "plan §8.3 (Proposed → Determined → Rehearsed → Approved → Posted → Disclosed → Closed)",
        format!(
            "inspect the case with `fa case show {ordinal} --json`; each transition is journaled once"
        ),
    )
}

fn fcw(detail: &str) -> Refusal {
    Refusal::new(
        code::CONFLICT,
        exit::CONFLICT,
        format!("a concurrent commit invalidated a witness this case record read: {detail}"),
        "FG-LAW-FCW-01 (first committer wins)",
        "retry; another record of the book's cases committed first",
    )
}

/// Authority before any read (doctrine 8): the `CaseControl` row's preparer
/// op for `act`, held by the acting principal for this book and current at
/// the head. A case record is a trunk record, so an Agent is refused.
fn admit<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    capability: &Capability,
    act: Act,
) -> Outcome<()> {
    let op = steward()?
        .transition_op("CaseControl", act.transition())
        .ok_or_else(|| {
            KernelError::Corrupt(format!(
                "sod_policy.toml registers no CaseControl {} rule; the record is refused, never unconstrained",
                act.transition()
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

/// A record's idempotency key: `H(domain ‖ act ‖ case ‖ caller key)`; an
/// Open record names no case (its ordinal is assigned at commit).
fn record_key(act: Act, case: Option<VId>, key: &[u8]) -> Vec<u8> {
    let case = case.map_or([0u8; 16], |vid| vid.0.to_le_bytes());
    domain_digest(RECORD_KEY_DOMAIN, &[&[act.tag()], &case, key]).to_vec()
}

#[allow(clippy::too_many_arguments)]
fn record_proposal(
    book: &BookContext,
    req: &CaseRequest,
    act: Act,
    case: VId,
    from: u8,
    to: CaseState,
    proof_refs: Vec<TypedRef>,
    spec_body_digest: [u8; 32],
    extension: (u16, Vec<u8>),
) -> EntryPayload {
    let named = match act {
        Act::Open => None,
        Act::Determine | Act::Rehearse => Some(case),
    };
    EntryPayload {
        schema_minor: fa_model::entry::SCHEMA_MINOR,
        book_id: book.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::CASE_CONTROL,
        effective_date: req.effective_date,
        document_date: None,
        description: req.description.clone(),
        effective_period: None,
        legs: Vec::new(),
        control: Some(ControlPayload::LifecycleTransition {
            object_ref: case,
            from,
            to: to.tag(),
            proof_refs,
            reason_code: 0,
        }),
        unit_totals: Vec::new(),
        base_totals: None,
        idempotency_key: record_key(act, named, &req.idempotency_key),
        origin: EntryOrigin::Control {
            control_kind: ControlKind::CASE_TRANSITION,
            spec_body_digest,
        },
        principal_ref: req.capability.holder(),
        session_ref: None,
        evidence: Vec::new(),
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: vec![extension],
        tags: Vec::new(),
    }
}

/// A document this book holds, verified.
fn witness_document<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    oid: &Oid,
    role: &str,
) -> Outcome<()> {
    let policy = EvidencePolicy::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let Some(row) = txn.vertex(db, document_vid(oid))? else {
        return Ok(Err(Refusal::new(
            code::EVIDENCE_UNKNOWN,
            exit::REFUSAL,
            format!(
                "the case's {role} document {} is not in this book",
                hex(&oid.0)
            ),
            "plan §8.3 (a case's narrative and determination authority are documents the book holds)",
            "record it first with `fa document add <file> --kind <Kind> --json` and name the oid it prints",
        )));
    };
    match verify_row(&row, &policy) {
        Ok(_) => Ok(Ok(())),
        Err(why) => Ok(Err(drift(oid, &why))),
    }
}

/// The identical record's sequence, or the conflict (plan §4.9: exact
/// bytes, else a seal-aware semantic comparison under the book key, since a
/// retry seals its description again).
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
        (Ok(_), Ok(_)) => Ok(Err(Refusal::new(
            code::IDEMPOTENCY_CONFLICT,
            exit::CONFLICT,
            format!(
                "this case record's identity holds different content; the recorded entry is {:032x}",
                row.vid.0
            ),
            "plan §4.9 (identity is derived from the key; content is bound by proposal_digest)",
            "resubmit the identical request to get its recorded outcome, or use a new --key",
        ))),
        (Err(fa_model::EntryError::Sealed(_)), _) | (_, Err(fa_model::EntryError::Sealed(_))) => {
            Ok(Err(Refusal::new(
                code::EQUIVALENCE_UNVERIFIABLE,
                exit::CONFLICT,
                format!(
                    "the recorded case record {:032x} has erased text, so a retry cannot be judged identical",
                    row.vid.0
                ),
                "plan §4.9, §14.6 (erasure leaves identity, not plaintext)",
                "use a new --key",
            )))
        }
        (Err(e), _) | (_, Err(e)) => Err(e.into()),
    }
}

/// The case body an Open record carries; `None` for any other entry.
fn opened_body(entry: &fa_model::Entry) -> Result<Option<CaseBody>, KernelError> {
    if entry.proposal.class != EntryClass::CASE_CONTROL {
        return Ok(None);
    }
    entry
        .proposal
        .extensions
        .iter()
        .find(|(tag, _)| *tag == fa_model::entry::RESTATEMENT_CASE_EXTENSION)
        .map(|(_, ext)| CaseBody::decode(ext))
        .transpose()
}

/// Open a case: one commit journaling the Open record, the
/// `RestatementCase` vertex at the book's next case ordinal with its
/// immutable body and `state`, and the record's `IN_CASE` edge to it.
/// `body.ordinal` is ignored and assigned here. An identical retry under the
/// same key returns the recorded case.
pub async fn open_case<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    mut body: CaseBody,
    req: CaseRequest,
) -> Outcome<CaseRecorded> {
    const FIX: &str = "fa case open --kind Restatement|Revision|PriorPeriodAdjustment|PolicyChangeRetrospective --periods <code>[,<code>]... [--narrative <oid>]";
    if body.book_id != book.book_id {
        return Ok(Err(usage("the restatement case names another book", FIX)));
    }
    body.periods.sort();
    body.periods.dedup();
    body.ordinal = 1;
    if let Err(why) = body.check() {
        return Ok(Err(usage(why, FIX)));
    }
    if let Err(r) = admit(db, book, &req.capability, Act::Open)? {
        return Ok(Err(r));
    }
    let principal = req.capability.holder();
    let evid = entry_vid(
        book.book_id,
        &principal.0.to_le_bytes(),
        &record_key(Act::Open, None, &req.idempotency_key),
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
        let (stored, _) = crate::post::entry_of(&row)?;
        let Some(recorded) = opened_body(&stored)? else {
            return Ok(Err(usage(
                "this case record's key names another kind of record",
                "use a new --key",
            )));
        };
        body.ordinal = recorded.ordinal;
        let proposal = open_proposal(book, &req, &body)?;
        return Ok(match recorded_or_conflict(book, &row, &proposal)? {
            Ok(recorded_at) => Ok(CaseRecorded {
                case: read_case(db, book, body.ordinal)?.ok_or_else(|| {
                    KernelError::Corrupt(format!(
                        "case record {:032x} has no RestatementCase vertex",
                        row.vid.0
                    ))
                })?,
                control_entry: evid,
                recorded_at,
                already_recorded: true,
            }),
            Err(r) => Err(r),
        });
    }
    for period in &body.periods {
        if txn
            .vertex(db, period_vid(&book.calendar.id, period))?
            .is_none()
        {
            txn.abort();
            return Ok(Err(crate::period::unknown_period(book, period)));
        }
    }
    // Every taken ordinal and the first free one are point witnesses, so a
    // case opened concurrently invalidates this one.
    let mut ordinal = 1_u32;
    while txn
        .vertex(db, restatement_case_vid(book.book_id, ordinal))?
        .is_some()
    {
        ordinal = ordinal
            .checked_add(1)
            .ok_or_else(|| KernelError::Corrupt("restatement case ordinals".into()))?;
    }
    body.ordinal = ordinal;
    for (oid, role) in body.narrative.iter().map(|oid| (oid, "narrative")).chain(
        body.determination
            .iter()
            .map(|d| (&d.authority, "authority")),
    ) {
        if let Err(r) = witness_document(&txn, db, oid, role)? {
            txn.abort();
            return Ok(Err(r));
        }
    }
    let proposal = open_proposal(book, &req, &body)?;
    if proposal.validate().is_err() {
        txn.abort();
        return Ok(Err(usage(
            "the Open record is not a valid CaseControl entry",
            FIX,
        )));
    }
    let entry = proposal.clone().seal(Vec::new(), None)?;
    let vid = body.vid();
    let state = opened_state(&body);
    let mut props = vec![
        (
            property::FA_PAYLOAD,
            scalar_bytes("case._fa_payload", body.canonical_bytes()?)?,
        ),
        (
            property::FA_DIGEST,
            scalar_bytes("case._fa_digest", body.digest()?.to_vec())?,
        ),
        (
            property::BOOK_ID,
            scalar_bytes("book_id", book.book_id.0.to_vec())?,
        ),
        (property::STATE, state.scalar()),
    ];
    props.sort_by_key(|(k, _)| k.0);
    let mut in_case = WriteBatch::new(relation::IN_CASE);
    in_case.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    in_case.create_vertex(vid, vec![label::RESTATEMENT_CASE], props);
    in_case.add_edge(edge_id(relation::IN_CASE, evid, vid), evid, vid, vec![]);
    txn.write(db, in_case)?;
    match txn.commit(db, &ctx.commit()).await {
        Ok(recorded_at) => Ok(Ok(CaseRecorded {
            case: read_case(db, book, ordinal)?.ok_or_else(|| {
                KernelError::Corrupt(format!("case {ordinal} vanished after its commit"))
            })?,
            control_entry: evid,
            recorded_at,
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(fcw(&detail)))
        }
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => Ok(Err(fcw(
            "another case took this ordinal, or this key's record committed concurrently",
        ))),
        Err(e) => Err(e.into()),
    }
}

/// The state an Open record leaves a case in.
fn opened_state(body: &CaseBody) -> CaseState {
    if body.determination.is_some() {
        CaseState::Determined
    } else {
        CaseState::Proposed
    }
}

fn open_proposal(
    book: &BookContext,
    req: &CaseRequest,
    body: &CaseBody,
) -> Result<EntryPayload, KernelError> {
    let proof_refs = body
        .narrative
        .iter()
        .chain(body.determination.iter().map(|d| &d.authority))
        .map(|oid| TypedRef::Object(*oid))
        .collect();
    Ok(record_proposal(
        book,
        req,
        Act::Open,
        body.vid(),
        0,
        opened_state(body),
        proof_refs,
        body.digest()?,
        (
            fa_model::entry::RESTATEMENT_CASE_EXTENSION,
            body.canonical_bytes()?,
        ),
    ))
}

/// Determine case `ordinal` (Proposed → Determined): one commit journaling
/// the Determine record, whose determination is the day and the authority
/// document, and the compare-and-set of the case's `state`.
pub async fn determine_case<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    ordinal: u32,
    determination: Determination,
    req: CaseRequest,
) -> Outcome<CaseRecorded> {
    if ordinal == 0 {
        return Ok(Err(unknown(ordinal)));
    }
    if let Err(r) = admit(db, book, &req.capability, Act::Determine)? {
        return Ok(Err(r));
    }
    let vid = restatement_case_vid(book.book_id, ordinal);
    let principal = req.capability.holder();
    let proposal = record_proposal(
        book,
        &req,
        Act::Determine,
        vid,
        CaseState::Proposed.tag(),
        CaseState::Determined,
        vec![TypedRef::Object(determination.authority)],
        domain_digest(DETERMINATION_DOMAIN, &[&determination.canonical_bytes()?]),
        (
            fa_model::entry::CASE_DETERMINATION_EXTENSION,
            determination.canonical_bytes()?,
        ),
    );
    let evid = entry_vid(
        book.book_id,
        &principal.0.to_le_bytes(),
        &proposal.idempotency_key,
    );
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    if let Err(r) = capability_witness(&txn, db, book, &req.capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    if let Some(row) = txn.vertex(db, evid)? {
        txn.abort();
        return Ok(match recorded_or_conflict(book, &row, &proposal)? {
            Ok(recorded_at) => Ok(CaseRecorded {
                case: read_case(db, book, ordinal)?
                    .ok_or_else(|| KernelError::Corrupt(format!("case {ordinal} vanished")))?,
                control_entry: evid,
                recorded_at,
                already_recorded: true,
            }),
            Err(r) => Err(r),
        });
    }
    let Some(row) = txn.vertex(db, vid)? else {
        txn.abort();
        return Ok(Err(unknown(ordinal)));
    };
    let state = CaseState::from_scalar(prop(&row, property::STATE))
        .ok_or_else(|| KernelError::Corrupt(format!("restatement case {ordinal} state mirror")))?;
    if state != CaseState::Proposed {
        txn.abort();
        return Ok(Err(wrong_state(ordinal, state, "Determine", "Proposed")));
    }
    if let Err(r) = witness_document(&txn, db, &determination.authority, "authority")? {
        txn.abort();
        return Ok(Err(r));
    }
    if proposal.validate().is_err() {
        txn.abort();
        return Ok(Err(usage(
            "the Determine record is not a valid CaseControl entry",
            "fa case determine <case> --on YYYY-MM-DD --authority <oid>",
        )));
    }
    let entry = proposal.clone().seal(Vec::new(), None)?;
    let mut batch = WriteBatch::new(relation::IN_CASE);
    batch.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    batch.compare_and_set_vertex_property(
        vid,
        property::STATE,
        Some(CaseState::Proposed.scalar()),
        CaseState::Determined.scalar(),
        WriteMismatchPolicy::AbortWrite,
    );
    batch.add_edge(edge_id(relation::IN_CASE, evid, vid), evid, vid, vec![]);
    txn.write(db, batch)?;
    match txn.commit(db, &ctx.commit()).await {
        Ok(recorded_at) => Ok(Ok(CaseRecorded {
            case: read_case(db, book, ordinal)?
                .ok_or_else(|| KernelError::Corrupt(format!("case {ordinal} vanished")))?,
            control_entry: evid,
            recorded_at,
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(fcw(&detail)))
        }
        Err(e) => Err(e.into()),
    }
}

fn rehearsal_refused(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::CASE_REHEARSAL,
        exit::REFUSAL,
        message.into(),
        "plan §8.3 (Rehearsed: on a branch, with the as-reported-vs-as-restated diff certificate attached)",
        "certify the scenario's diff over every period the case affects (fa scenario diff <name> --period <code>... --certify --certificate-out <file>) while the scenario is open, then rehearse with that certificate",
    )
}

/// Rehearse case `ordinal` (Determined → Rehearsed): one commit journaling
/// the Rehearse record and the compare-and-set of the case's `state`. The
/// caller has replayed the diff certificate and retained it in this book;
/// this record witnesses the retained certificate and the open scenario, and
/// refuses a diff that does not cover every period the case affects.
pub async fn rehearse_case<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    ordinal: u32,
    rehearsal: Rehearsal,
    req: CaseRequest,
) -> Outcome<CaseRecorded> {
    const FIX: &str = "fa case rehearse <case> --certificate <scenario-diff-certificate>";
    if ordinal == 0 {
        return Ok(Err(unknown(ordinal)));
    }
    if let Err(why) = rehearsal.check() {
        return Ok(Err(usage(why, FIX)));
    }
    if let Err(r) = admit(db, book, &req.capability, Act::Rehearse)? {
        return Ok(Err(r));
    }
    let vid = restatement_case_vid(book.book_id, ordinal);
    let scenario = scenario_vid(book.book_id, &rehearsal.scenario);
    let certificate = report_certificate_vid(book.book_id, &rehearsal.certificate);
    let principal = req.capability.holder();
    let proposal = record_proposal(
        book,
        &req,
        Act::Rehearse,
        vid,
        CaseState::Determined.tag(),
        CaseState::Rehearsed,
        vec![TypedRef::Vertex(certificate), TypedRef::Vertex(scenario)],
        domain_digest(REHEARSAL_DOMAIN, &[&rehearsal.canonical_bytes()?]),
        (
            fa_model::entry::CASE_REHEARSAL_EXTENSION,
            rehearsal.canonical_bytes()?,
        ),
    );
    let evid = entry_vid(
        book.book_id,
        &principal.0.to_le_bytes(),
        &proposal.idempotency_key,
    );
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    if let Err(r) = capability_witness(&txn, db, book, &req.capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    if let Some(row) = txn.vertex(db, evid)? {
        txn.abort();
        return Ok(match recorded_or_conflict(book, &row, &proposal)? {
            Ok(recorded_at) => Ok(CaseRecorded {
                case: read_case(db, book, ordinal)?
                    .ok_or_else(|| KernelError::Corrupt(format!("case {ordinal} vanished")))?,
                control_entry: evid,
                recorded_at,
                already_recorded: true,
            }),
            Err(r) => Err(r),
        });
    }
    let Some(row) = txn.vertex(db, vid)? else {
        txn.abort();
        return Ok(Err(unknown(ordinal)));
    };
    let state = CaseState::from_scalar(prop(&row, property::STATE))
        .ok_or_else(|| KernelError::Corrupt(format!("restatement case {ordinal} state mirror")))?;
    if state != CaseState::Determined {
        txn.abort();
        return Ok(Err(wrong_state(ordinal, state, "Rehearse", "Determined")));
    }
    let body = CaseBody::decode(&bytes(&row, property::FA_PAYLOAD, "case._fa_payload")?)?;
    let missing: Vec<&str> = body
        .periods
        .iter()
        .filter(|p| rehearsal.periods.binary_search(p).is_err())
        .map(String::as_str)
        .collect();
    if !missing.is_empty() {
        txn.abort();
        return Ok(Err(rehearsal_refused(format!(
            "the diff certificate covers {} but case {ordinal} affects {} as well",
            rehearsal.periods.join(", "),
            missing.join(", ")
        ))));
    }
    match txn.vertex(db, certificate)? {
        Some(row) if row.labels.as_slice() == [label::CERTIFICATE] => {}
        _ => {
            txn.abort();
            return Ok(Err(rehearsal_refused(format!(
                "diff certificate {} is not retained in this book",
                hex(&rehearsal.certificate)
            ))));
        }
    }
    match txn.vertex(db, scenario)? {
        Some(row)
            if row.labels.contains(&label::SCENARIO)
                && crate::scenario::ScenarioState::from_scalar(prop(&row, property::STATE))
                    == Some(crate::scenario::ScenarioState::Open) => {}
        Some(_) => {
            txn.abort();
            return Ok(Err(rehearsal_refused(format!(
                "scenario `{}` is not open: a discarded scenario is no rehearsal",
                rehearsal.scenario
            ))));
        }
        None => {
            txn.abort();
            return Ok(Err(rehearsal_refused(format!(
                "this book has no scenario `{}`",
                rehearsal.scenario
            ))));
        }
    }
    // The Plan records are immutable; the open scenario's planning order
    // must begin with exactly the ones the diff certificate covers.
    let planned: Vec<VId> = crate::scenario::read_scenario(db, book, &rehearsal.scenario)?
        .map(|view| view.intents.iter().map(|p| p.record).collect())
        .unwrap_or_default();
    if !planned.starts_with(&rehearsal.intents) {
        txn.abort();
        return Ok(Err(rehearsal_refused(format!(
            "the diff certificate covers {} intent(s) that are not the first ones scenario `{}` planned",
            rehearsal.intents.len(),
            rehearsal.scenario
        ))));
    }
    if proposal.validate().is_err() {
        txn.abort();
        return Ok(Err(usage(
            "the Rehearse record is not a valid CaseControl entry",
            FIX,
        )));
    }
    let entry = proposal.clone().seal(Vec::new(), None)?;
    let mut batch = WriteBatch::new(relation::IN_CASE);
    batch.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    batch.compare_and_set_vertex_property(
        vid,
        property::STATE,
        Some(CaseState::Determined.scalar()),
        CaseState::Rehearsed.scalar(),
        WriteMismatchPolicy::AbortWrite,
    );
    batch.add_edge(edge_id(relation::IN_CASE, evid, vid), evid, vid, vec![]);
    txn.write(db, batch)?;
    match txn.commit(db, &ctx.commit()).await {
        Ok(recorded_at) => Ok(Ok(CaseRecorded {
            case: read_case(db, book, ordinal)?
                .ok_or_else(|| KernelError::Corrupt(format!("case {ordinal} vanished")))?,
            control_entry: evid,
            recorded_at,
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(fcw(&detail)))
        }
        Err(e) => Err(e.into()),
    }
}

/// Case `ordinal` as its records state it, each cross-checked against its
/// vertex, at the head.
pub fn read_case<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    ordinal: u32,
) -> Result<Option<CaseView>, KernelError> {
    let vid = restatement_case_vid(book.book_id, ordinal);
    match db.vertex(vid)? {
        Some(row) => view_of(db, book, &row).map(Some),
        None => Ok(None),
    }
}

/// Every case of the book, by ordinal.
pub fn list_cases<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
) -> Result<Vec<CaseView>, KernelError> {
    let mut out = Vec::new();
    let mut ordinal = 1_u32;
    while let Some(view) = read_case(db, book, ordinal)? {
        out.push(view);
        ordinal = ordinal
            .checked_add(1)
            .ok_or_else(|| KernelError::Corrupt("restatement case ordinals".into()))?;
    }
    Ok(out)
}

fn view_of<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    row: &VertexRow,
) -> Result<CaseView, KernelError> {
    let vid = row.vid;
    if row.labels.as_slice() != [label::RESTATEMENT_CASE] {
        return Err(KernelError::Corrupt(format!(
            "case identity {:032x} holds a vertex that is not a RestatementCase",
            vid.0
        )));
    }
    let body = CaseBody::decode(&bytes(row, property::FA_PAYLOAD, "case._fa_payload")?)?;
    if body.vid() != vid || body.book_id != book.book_id {
        return Err(KernelError::Corrupt(format!(
            "restatement case {:032x} carries another case's body",
            vid.0
        )));
    }
    let state = CaseState::from_scalar(prop(row, property::STATE))
        .ok_or_else(|| KernelError::Corrupt(format!("restatement case {:032x} state", vid.0)))?;
    let mut transitions = Vec::new();
    let mut determination = body.determination;
    let mut rehearsal = None;
    for evid in db.in_neighbours(vid, relation::IN_CASE)? {
        let Some(src) = db.vertex(evid)? else {
            continue;
        };
        if !src.labels.contains(&label::ENTRY) {
            continue;
        }
        let (entry, recorded_at) = crate::post::entry_of(&src)?;
        if entry.proposal.class != EntryClass::CASE_CONTROL {
            continue;
        }
        let Some(ControlPayload::LifecycleTransition {
            object_ref,
            from,
            to,
            ..
        }) = &entry.proposal.control
        else {
            return Err(KernelError::Corrupt(format!(
                "case record {:032x} carries no LifecycleTransition",
                evid.0
            )));
        };
        if *object_ref != vid {
            return Err(KernelError::Corrupt(format!(
                "case record {:032x} names another case",
                evid.0
            )));
        }
        let to = CaseState::from_tag(*to)
            .ok_or_else(|| KernelError::Corrupt(format!("case record {:032x} state", evid.0)))?;
        let from = if *from == 0 {
            if opened_body(&entry)?.as_ref() != Some(&body) {
                return Err(KernelError::Corrupt(format!(
                    "case record {:032x} opened another body",
                    evid.0
                )));
            }
            None
        } else {
            Some(CaseState::from_tag(*from).ok_or_else(|| {
                KernelError::Corrupt(format!("case record {:032x} state", evid.0))
            })?)
        };
        if let Some((_, ext)) = entry
            .proposal
            .extensions
            .iter()
            .find(|(tag, _)| *tag == fa_model::entry::CASE_DETERMINATION_EXTENSION)
        {
            determination = Some(Determination::decode(ext)?);
        }
        if let Some((_, ext)) = entry
            .proposal
            .extensions
            .iter()
            .find(|(tag, _)| *tag == fa_model::entry::CASE_REHEARSAL_EXTENSION)
        {
            rehearsal = Some(Rehearsal::decode(ext)?);
        }
        transitions.push(CaseTransition {
            from,
            to,
            control_entry: evid,
            recorded_at,
            principal: entry.proposal.principal_ref,
        });
    }
    transitions.sort_by_key(|t| (t.recorded_at, t.control_entry));
    // The records form one chain from the Open record to the mirrored state.
    let chained = transitions.first().is_some_and(|t| t.from.is_none())
        && transitions.windows(2).all(|w| w[1].from == Some(w[0].to))
        && transitions.last().map(|t| t.to) == Some(state);
    if !chained {
        return Err(KernelError::Corrupt(format!(
            "restatement case {} records do not chain to its {} state",
            body.ordinal,
            state.name()
        )));
    }
    Ok(CaseView {
        vid,
        body,
        state,
        determination,
        rehearsal,
        transitions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body() -> CaseBody {
        CaseBody {
            book_id: Id128([7; 16]),
            ordinal: 1,
            kind: CaseKind::Restatement,
            periods: vec!["FY2025-P11".into(), "FY2025-P12".into()],
            narrative: Some(Oid([3; 32])),
            determination: Some(Determination {
                day: DateDay(20_000),
                authority: Oid([4; 32]),
            }),
        }
    }

    #[test]
    fn a_case_body_round_trips_and_every_field_moves_its_digest() {
        let base = body();
        assert_eq!(
            CaseBody::decode(&base.canonical_bytes().unwrap()).unwrap(),
            base
        );
        let variants = [
            CaseBody {
                ordinal: 2,
                ..base.clone()
            },
            CaseBody {
                kind: CaseKind::Revision,
                ..base.clone()
            },
            CaseBody {
                periods: vec!["FY2025-P12".into()],
                ..base.clone()
            },
            CaseBody {
                narrative: None,
                ..base.clone()
            },
            CaseBody {
                determination: None,
                ..base.clone()
            },
        ];
        for v in &variants {
            assert_ne!(v.digest().unwrap(), base.digest().unwrap(), "{v:?}");
        }
        assert_ne!(variants[0].vid(), base.vid(), "the ordinal is the identity");
        assert_eq!(variants[1].vid(), base.vid());
        let d = base.determination.unwrap();
        assert_eq!(
            Determination::decode(&d.canonical_bytes().unwrap()).unwrap(),
            d
        );
    }

    #[test]
    fn a_rehearsal_round_trips_and_refuses_bytes_out_of_its_domain() {
        let base = Rehearsal {
            scenario: "restated".into(),
            certificate: [9; 32],
            fork_at: CommitSeq(41),
            periods: vec!["FY2025-P11".into(), "FY2025-P12".into()],
            intents: vec![VId(5), VId(3)],
        };
        let bytes = base.canonical_bytes().unwrap();
        assert_eq!(Rehearsal::decode(&bytes).unwrap(), base);
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(Rehearsal::decode(&trailing).is_err(), "trailing byte");
        for bad in [
            Rehearsal {
                scenario: String::new(),
                ..base.clone()
            },
            Rehearsal {
                periods: Vec::new(),
                ..base.clone()
            },
            Rehearsal {
                periods: vec!["FY2025-P12".into(), "FY2025-P11".into()],
                ..base.clone()
            },
            Rehearsal {
                intents: vec![VId(5), VId(5)],
                ..base.clone()
            },
        ] {
            assert!(bad.check().is_err(), "{bad:?}");
            assert!(
                Rehearsal::decode(&bad.canonical_bytes().unwrap()).is_err(),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_case_body_out_of_its_domain_or_with_trailing_bytes_is_refused() {
        let mut bytes = body().canonical_bytes().unwrap();
        bytes.push(0);
        assert!(CaseBody::decode(&bytes).is_err(), "trailing byte");
        for bad in [
            CaseBody {
                ordinal: 0,
                ..body()
            },
            CaseBody {
                periods: Vec::new(),
                ..body()
            },
            CaseBody {
                periods: vec!["FY2025-P12".into(), "FY2025-P11".into()],
                ..body()
            },
            CaseBody {
                periods: vec!["FY2025-P12".into(), "FY2025-P12".into()],
                ..body()
            },
        ] {
            assert!(bad.check().is_err(), "{bad:?}");
            assert!(
                CaseBody::decode(&bad.canonical_bytes().unwrap()).is_err(),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn kinds_and_states_have_one_tag_and_one_name() {
        for k in CaseKind::ALL {
            assert_eq!(CaseKind::from_tag(k.tag()), Some(k));
            assert_eq!(CaseKind::parse(k.name()), Some(k));
        }
        for s in CaseState::ALL {
            assert_eq!(CaseState::from_tag(s.tag()), Some(s));
            assert_eq!(CaseState::from_scalar(Some(&s.scalar())), Some(s));
        }
        assert_eq!(CaseKind::from_tag(0), None);
        assert_eq!(CaseState::from_tag(0), None);
        assert_eq!(CaseState::from_tag(8), None);
    }
}
