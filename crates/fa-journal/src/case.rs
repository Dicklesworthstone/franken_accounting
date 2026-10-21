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
//! - **Approve** (`Rehearsed → Approved`) journals the case's effect
//!   manifest in extension 22 `fa:case-approval:v1`: the case, its body and
//!   rehearsal digests, and for each Plan record the rehearsal names, its
//!   intent's digest and its planner. Two Human approvals of the manifest's
//!   digest are cited (`case-approve`), and no approver planned any of the
//!   case's entries (the `case_preparer` exclusion, decided here).
//! - **Post** (`Approved → Posted`) posts the case's entries as one atomic
//!   batch and journals extension 24 `fa:case-posted:v1` naming them, in
//!   one commit.
//!   Each entry is the kernel's derivation of one manifest entry
//!   ([`derive_member`]): the planned intent as the case's class, under the
//!   poster, with extension 23 `fa:case-member:v1`. The posting law admits
//!   a case-bound class only as such a derivation of an Approved case, and
//!   decides its row's approvals over the case's approvals ([`admit_member`]).
//!   This build posts PriorPeriodAdjustment and Revision cases. A Revision
//!   case's entries are Revision entries that each revise one standing
//!   posting (`Revises`, net effect target plus delta) in a period the
//!   case affects. Restatement entries wait for their SoD rule's session
//!   lineage (fa-651f).
//! - **Disclose** (`Posted → Disclosed`) journals extension 25
//!   `fa:case-disclosure:v1`: the Disclosure document the case is disclosed
//!   in and the Reviewed attestation over it, which a principal other than
//!   the document's uploader recorded (plan §9.3); both are point witnesses.
//! - **Close** (`Disclosed → Closed`) is the case's last record.
//!
//! The narrative and authority documents are the records' proof refs and
//! must be verified documents of this book; every affected period must
//! exist. The vertex's `state` moves by compare-and-set, so two concurrent
//! transitions of one case race and the first committer wins.
//!
//! **Authority.** Every record is a trunk record under `restate`
//! (`sod_policy.toml` `case-open`, `case-determine`, `case-rehearse`,
//! `case-approve`, `case-post`, `case-disclose`, `case-close`); an Agent
//! prepares none.

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
const MANIFEST_DOMAIN: &[u8] = b"fa:case-approval:v1";
const MANIFEST_ENTRY_DOMAIN: &[u8] = b"fa:case-manifest-entry:v1";
/// Canonical bytes of an approved manifest (extension 22).
pub const MANIFEST_VERSION: u16 = 1;
/// Canonical bytes of a case member (extension 23) and of a Post record's
/// entries (extension 24).
pub const MEMBER_VERSION: u16 = 1;
pub const POSTED_VERSION: u16 = 1;
const MEMBER_KEY_DOMAIN: &[u8] = b"fa:case-member-key:v1";
const POST_BATCH_KEY_DOMAIN: &[u8] = b"fa:case-post-batch-key:v1";
const POSTED_DOMAIN: &[u8] = b"fa:case-posted:v1";
/// Canonical bytes of a disclosure (extension 25).
pub const DISCLOSURE_VERSION: u16 = 1;
const DISCLOSURE_DOMAIN: &[u8] = b"fa:case-disclosure:v1";
const CLOSE_DOMAIN: &[u8] = b"fa:case-close:v1";
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

/// One entry the case will post: the scenario's Plan record, the digest of
/// its intent, and the principal who planned it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManifestEntry {
    pub plan: VId,
    pub intent: [u8; 32],
    pub planner: VId,
}

/// A case's effect manifest (plan §8.3): the exact ordered entries its
/// approvals bind, with the body and rehearsal they belong to. Its digest is
/// what each approver approves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaseManifest {
    pub case: VId,
    pub body_digest: [u8; 32],
    pub rehearsal_digest: [u8; 32],
    pub entries: Vec<ManifestEntry>,
}

impl CaseManifest {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, KernelError> {
        let mut w = Writer::with_capacity(96 + self.entries.len() * 64);
        w.u16(MANIFEST_VERSION)
            .u128(self.case.0)
            .fixed(&self.body_digest)
            .fixed(&self.rehearsal_digest)
            .list(&self.entries, |w, e| {
                w.u128(e.plan.0).fixed(&e.intent).u128(e.planner.0);
            });
        Ok(w.finish()?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, KernelError> {
        let mut r = Reader::new(bytes);
        if r.u16("case.manifest.version").map_err(decode)? != MANIFEST_VERSION {
            return Err(KernelError::Corrupt(
                "unsupported case manifest version".into(),
            ));
        }
        let case = VId(r.u128("case.manifest.case").map_err(decode)?);
        let body_digest = r.fixed("case.manifest.body").map_err(decode)?;
        let rehearsal_digest = r.fixed("case.manifest.rehearsal").map_err(decode)?;
        let entries = r
            .list(MAX_BATCH_ENTRIES, "case.manifest.entries", |r| {
                Ok(ManifestEntry {
                    plan: VId(r.u128("case.manifest.plan")?),
                    intent: r.fixed("case.manifest.intent")?,
                    planner: VId(r.u128("case.manifest.planner")?),
                })
            })
            .map_err(decode)?;
        r.finish().map_err(decode)?;
        Ok(Self {
            case,
            body_digest,
            rehearsal_digest,
            entries,
        })
    }

    /// The digest the case's approvals bind.
    pub fn digest(&self) -> Result<[u8; 32], KernelError> {
        Ok(domain_digest(MANIFEST_DOMAIN, &[&self.canonical_bytes()?]))
    }

    /// The principals who prepared any of the case's entries.
    #[must_use]
    pub fn preparers(&self) -> std::collections::BTreeSet<VId> {
        self.entries.iter().map(|e| e.planner).collect()
    }
}

/// The Approve record: the manifest and the approvals it cites.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaseApproval {
    pub manifest: CaseManifest,
    pub approvals: Vec<fa_model::ApprovalRef>,
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
    /// The approved manifest and its approvals, from the Approve record.
    pub approval: Option<CaseApproval>,
    /// The entries the Post record names, in manifest order.
    pub posted: Vec<PostedEntry>,
    /// The disclosure, from the Disclose record.
    pub disclosure: Option<Disclosure>,
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
    Approve,
    Post,
    Disclose,
    Close,
}

impl Act {
    fn transition(self) -> &'static str {
        match self {
            Self::Open => "Open",
            Self::Determine => "Determine",
            Self::Rehearse => "Rehearse",
            Self::Approve => "Approve",
            Self::Post => "Post",
            Self::Disclose => "Disclose",
            Self::Close => "Close",
        }
    }

    fn tag(self) -> u8 {
        match self {
            Self::Open => 0,
            Self::Determine => 1,
            Self::Rehearse => 2,
            Self::Approve => 3,
            Self::Post => 4,
            Self::Disclose => 5,
            Self::Close => 6,
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
    extension: Option<(u16, Vec<u8>)>,
) -> EntryPayload {
    let named = match act {
        Act::Open => None,
        Act::Determine | Act::Rehearse | Act::Approve | Act::Post | Act::Disclose | Act::Close => {
            Some(case)
        }
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
        extensions: extension.into_iter().collect(),
        tags: Vec::new(),
    }
}

/// A document this book holds, verified.
fn witness_document<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    oid: &Oid,
    role: &str,
) -> Outcome<crate::evidence::DocumentRecord> {
    let policy = EvidencePolicy::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let Some(row) = txn.vertex(db, document_vid(oid))? else {
        return Ok(Err(Refusal::new(
            code::EVIDENCE_UNKNOWN,
            exit::REFUSAL,
            format!(
                "the case's {role} document {} is not in this book",
                hex(&oid.0)
            ),
            "plan §8.3 (a case's narrative, authority and disclosure are documents the book holds)",
            "record it first with `fa document add <file> --kind <Kind> --json` and name the oid it prints",
        )));
    };
    match verify_row(&row, &policy) {
        Ok(record) => Ok(Ok(record)),
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
        Some((
            fa_model::entry::RESTATEMENT_CASE_EXTENSION,
            body.canonical_bytes()?,
        )),
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
        Some((
            fa_model::entry::CASE_DETERMINATION_EXTENSION,
            determination.canonical_bytes()?,
        )),
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
        Some((
            fa_model::entry::CASE_REHEARSAL_EXTENSION,
            rehearsal.canonical_bytes()?,
        )),
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

/// The effect manifest of a Rehearsed case: for each Plan record its
/// rehearsal names, in order, the intent's digest and its planner, under the
/// case's body and rehearsal digests.
fn manifest_of<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    view: &CaseView,
) -> Outcome<CaseManifest> {
    let ordinal = view.body.ordinal;
    let (CaseState::Rehearsed, Some(rehearsal)) = (view.state, view.rehearsal.as_ref()) else {
        return Ok(Err(wrong_state(
            ordinal,
            view.state,
            "Approve",
            "Rehearsed",
        )));
    };
    let Some(scenario) = crate::scenario::read_scenario(db, book, &rehearsal.scenario)? else {
        return Ok(Err(rehearsal_refused(format!(
            "case {ordinal}'s scenario `{}` is not in this book",
            rehearsal.scenario
        ))));
    };
    let mut entries = Vec::with_capacity(rehearsal.intents.len());
    for plan in &rehearsal.intents {
        let Some(planned) = scenario.intents.iter().find(|p| p.record == *plan) else {
            return Ok(Err(rehearsal_refused(format!(
                "case {ordinal}'s Plan record {:032x} is not in scenario `{}`",
                plan.0, rehearsal.scenario
            ))));
        };
        let intent = planned
            .intent
            .canonical_bytes()
            .map_err(|e| KernelError::Corrupt(format!("case manifest intent: {e}")))?;
        entries.push(ManifestEntry {
            plan: *plan,
            intent: domain_digest(MANIFEST_ENTRY_DOMAIN, &[&intent]),
            planner: planned.capability.holder(),
        });
    }
    Ok(Ok(CaseManifest {
        case: view.vid,
        body_digest: view.body.digest()?,
        rehearsal_digest: domain_digest(REHEARSAL_DOMAIN, &[&rehearsal.canonical_bytes()?]),
        entries,
    }))
}

/// The manifest case `ordinal`'s approvers approve (plan §8.3): its digest is
/// what `fa approve --proposal` binds. The case must be Rehearsed.
pub fn case_manifest<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    ordinal: u32,
) -> Outcome<CaseManifest> {
    match read_case(db, book, ordinal)? {
        Some(view) => manifest_of(db, book, &view),
        None => Ok(Err(unknown(ordinal))),
    }
}

/// Approve case `ordinal` (Rehearsed → Approved): one commit journaling the
/// Approve record, which carries the effect manifest and cites `approvals`
/// (Approval vertices, each bound here to the manifest's digest), and the
/// compare-and-set of the case's `state`.
/// The `case-approve` rule decides the approvals inside the transaction,
/// with the manifest's planners as the case's preparers.
pub async fn approve_case<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    ordinal: u32,
    approvals: Vec<VId>,
    req: CaseRequest,
) -> Outcome<CaseRecorded> {
    const FIX: &str = "fa case approve <case> --approval <vid> --approval <vid>";
    if ordinal == 0 {
        return Ok(Err(unknown(ordinal)));
    }
    if let Err(r) = admit(db, book, &req.capability, Act::Approve)? {
        return Ok(Err(r));
    }
    let vid = restatement_case_vid(book.book_id, ordinal);
    let principal = req.capability.holder();
    // The manifest derives from immutable records (the body, the one
    // Rehearse record, the Plan records), so it is fixed once the case is
    // Rehearsed; the state is witnessed and compare-and-set below.
    let Some(view) = read_case(db, book, ordinal)? else {
        return Ok(Err(unknown(ordinal)));
    };
    let manifest = if view.state == CaseState::Approved {
        match &view.approval {
            Some(a) => a.manifest.clone(),
            None => {
                return Err(KernelError::Corrupt(format!(
                    "approved case {ordinal} carries no approval record"
                )));
            }
        }
    } else {
        match manifest_of(db, book, &view)? {
            Ok(manifest) => manifest,
            Err(r) => return Ok(Err(r)),
        }
    };
    let digest = manifest.digest()?;
    let approvals: Vec<fa_model::ApprovalRef> = approvals
        .into_iter()
        .map(|approval_vid| fa_model::ApprovalRef {
            approval_vid,
            approved_digest: digest,
        })
        .collect();
    let proposal = record_proposal(
        book,
        &req,
        Act::Approve,
        vid,
        CaseState::Rehearsed.tag(),
        CaseState::Approved,
        manifest
            .entries
            .iter()
            .map(|e| TypedRef::Vertex(e.plan))
            .collect(),
        digest,
        Some((
            fa_model::entry::CASE_APPROVAL_EXTENSION,
            manifest.canonical_bytes()?,
        )),
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
    if state != CaseState::Rehearsed {
        txn.abort();
        return Ok(Err(wrong_state(ordinal, state, "Approve", "Rehearsed")));
    }
    // Segregation of duties (plan §8.3, §14.3): two Human approvals of
    // exactly this manifest under the current epoch, none by a principal
    // who planned any of the case's entries.
    let epoch = crate::policy::epoch_witness(&txn, db)?;
    let key = fa_policy::sod::control_key("CaseControl", None, "Approve");
    let preparer = fa_policy::Party {
        principal,
        profile: req.capability.profile(),
    };
    let preparers = manifest.preparers();
    if let Err(r) = crate::policy::authorize_approvals_in(
        &txn,
        db,
        book,
        &approvals,
        &digest,
        epoch,
        &key,
        0,
        preparer,
        Some(&preparers),
    )? {
        txn.abort();
        return Ok(Err(r));
    }
    if proposal.validate().is_err() {
        txn.abort();
        return Ok(Err(usage(
            "the Approve record is not a valid CaseControl entry",
            FIX,
        )));
    }
    let entry = proposal.clone().seal(approvals, None)?;
    let mut batch = WriteBatch::new(relation::IN_CASE);
    batch.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    batch.compare_and_set_vertex_property(
        vid,
        property::STATE,
        Some(CaseState::Rehearsed.scalar()),
        CaseState::Approved.scalar(),
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

/// The token [`crate::post::Admission::Case`] carries. Only this module
/// makes one, in [`post_case`], so a case's entry reaches trunk only in its
/// case's batch, with its Post record and state change.
#[derive(Clone, Copy, Debug)]
pub struct Posting(());

/// A posting entry's claim to belong to a case (extension 23).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaseMember {
    pub ordinal: u32,
    /// The scenario's Plan record the entry derives from.
    pub plan: VId,
}

impl CaseMember {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, KernelError> {
        let mut w = Writer::with_capacity(24);
        w.u16(MEMBER_VERSION).u32(self.ordinal).u128(self.plan.0);
        Ok(w.finish()?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, KernelError> {
        let mut r = Reader::new(bytes);
        if r.u16("case.member.version").map_err(decode)? != MEMBER_VERSION {
            return Err(KernelError::Corrupt(
                "unsupported case member version".into(),
            ));
        }
        let member = Self {
            ordinal: r.u32("case.member.ordinal").map_err(decode)?,
            plan: VId(r.u128("case.member.plan").map_err(decode)?),
        };
        r.finish().map_err(decode)?;
        Ok(member)
    }
}

/// One posted entry of a Post record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PostedEntry {
    pub plan: VId,
    pub entry: VId,
    pub entry_digest: [u8; 32],
}

fn posted_bytes(entries: &[PostedEntry]) -> Result<Vec<u8>, KernelError> {
    let mut w = Writer::with_capacity(8 + entries.len() * 64);
    w.u16(POSTED_VERSION).list(entries, |w, e| {
        w.u128(e.plan.0).u128(e.entry.0).fixed(&e.entry_digest);
    });
    Ok(w.finish()?)
}

fn decode_posted(bytes: &[u8]) -> Result<Vec<PostedEntry>, KernelError> {
    let mut r = Reader::new(bytes);
    if r.u16("case.posted.version").map_err(decode)? != POSTED_VERSION {
        return Err(KernelError::Corrupt(
            "unsupported case posted version".into(),
        ));
    }
    let entries = r
        .list(MAX_BATCH_ENTRIES, "case.posted.entries", |r| {
            Ok(PostedEntry {
                plan: VId(r.u128("case.posted.plan")?),
                entry: VId(r.u128("case.posted.entry")?),
                entry_digest: r.fixed("case.posted.digest")?,
            })
        })
        .map_err(decode)?;
    r.finish().map_err(decode)?;
    Ok(entries)
}

/// The class a case of `kind` posts its entries as in this build.
/// Restatement entries wait for their SoD rule's session lineage
/// (fa-651f); PolicyChangeRetrospective posts Restatement entries.
#[must_use]
pub fn posting_class(kind: CaseKind) -> Option<EntryClass> {
    match kind {
        CaseKind::PriorPeriodAdjustment => Some(EntryClass::PRIOR_PERIOD_ADJUSTMENT),
        CaseKind::Revision => Some(EntryClass::REVISION),
        CaseKind::Restatement | CaseKind::PolicyChangeRetrospective => None,
    }
}

/// The classes only a restatement case posts (plan §8.3): on trunk each
/// is admitted only as its Approved case's entry, in the case's own Post.
#[must_use]
pub(crate) fn case_bound(class: EntryClass) -> bool {
    matches!(
        class,
        EntryClass::PRIOR_PERIOD_ADJUSTMENT | EntryClass::REVISION
    )
}

/// The trunk entry case `ordinal` (of `kind`) posts for its manifest entry
/// planned as `planned` in Plan record `plan`, posted by `principal`: the
/// planned proposal as the case's class, under the poster, keyed by the
/// case and the Plan record, carrying extension 23. Deterministic: the
/// posting law recomputes it to admit the entry.
pub fn derive_member(
    book_id: Id128,
    kind: CaseKind,
    ordinal: u32,
    plan: VId,
    planned: &EntryPayload,
    principal: VId,
) -> Result<Result<EntryPayload, Refusal>, KernelError> {
    let Some(class) = posting_class(kind) else {
        return Ok(Err(membership(format!(
            "a {} case's entries supersede a target with delta legs, which this build does not post",
            kind.name()
        ))));
    };
    // A Revision case's Plan record is a Revision that revises one target;
    // any other case plans plain postings that post as its class.
    if class == EntryClass::REVISION {
        let revises = matches!(
            planned.supersession.as_slice(),
            [s] if s.kind == fa_model::SupersessionKind::Revises
        );
        if planned.class != EntryClass::REVISION || !revises || planned.pending.is_some() {
            return Ok(Err(membership(format!(
                "a Revision case posts Revision entries that each revise one target (supersession Revises), and this Plan record is a {}",
                planned.class.name().unwrap_or("?")
            ))));
        }
    } else if !matches!(planned.class, EntryClass::ORIGINAL | EntryClass::ADJUSTING)
        || !planned.supersession.is_empty()
        || planned.pending.is_some()
    {
        return Ok(Err(membership(format!(
            "a case posts plain postings: its Plan records are Original or Adjusting entries without supersession or a hold, and this one is a {}",
            planned.class.name().unwrap_or("?")
        ))));
    }
    if planned
        .extensions
        .iter()
        .any(|(tag, _)| *tag == fa_model::entry::BALANCING_EXTENSION)
    {
        return Ok(Err(membership(
            "a case posts entries whose legs its approvers saw: a balancing request resolves its legs at commit, so it is not a case's entry",
        )));
    }
    let case = restatement_case_vid(book_id, ordinal);
    let mut proposal = planned.clone();
    proposal.class = class;
    proposal.principal_ref = principal;
    proposal.idempotency_key = domain_digest(
        MEMBER_KEY_DOMAIN,
        &[&case.0.to_le_bytes(), &plan.0.to_le_bytes()],
    )
    .to_vec();
    proposal
        .extensions
        .retain(|(tag, _)| *tag != fa_model::entry::CASE_MEMBER_EXTENSION);
    proposal.extensions.push((
        fa_model::entry::CASE_MEMBER_EXTENSION,
        CaseMember { ordinal, plan }.canonical_bytes()?,
    ));
    proposal.extensions.sort_by_key(|(tag, _)| *tag);
    // An extension block needs schema minor 1 (Appendix A); a Plan record
    // written at minor 0 has none.
    proposal.schema_minor = proposal.schema_minor.max(fa_model::entry::SCHEMA_MINOR);
    Ok(Ok(proposal))
}

fn membership(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::CASE_MEMBERSHIP,
        exit::REFUSAL,
        message.into(),
        "plan §8.3, §8.4 (a case-bound entry is admissible only inside an Approved RestatementCase)",
        "post a case's entries with `fa case post <case>` after two Human approvals of its manifest",
    )
}

/// The case a posting entry claims (extension 23), checked against its
/// class and `admission`: a case-bound class needs the claim and the case's
/// own Post (whose admission carries nothing else); any other class may not
/// carry it.
pub(crate) fn member_of(
    proposal: &EntryPayload,
    admission: crate::post::Admission,
) -> Result<Result<Option<CaseMember>, Refusal>, KernelError> {
    let claim = proposal
        .extensions
        .iter()
        .find(|(tag, _)| *tag == fa_model::entry::CASE_MEMBER_EXTENSION);
    let case_bound = case_bound(proposal.class);
    let posting = matches!(admission, crate::post::Admission::Case(_));
    let rehearsing = matches!(admission, crate::post::Admission::ScratchScenario(_));
    match (claim, case_bound, posting) {
        (Some((_, bytes)), true, true) => Ok(Ok(Some(CaseMember::decode(bytes)?))),
        // A scenario's scratch replay rehearses the class without its case.
        (None, true, false) if rehearsing => Ok(Ok(None)),
        (_, true, false) => Ok(Err(membership(format!(
            "a {} entry belongs to a restatement case: it is posted only in its case's batch, with the case's Post record",
            proposal.class.name().unwrap_or("?")
        )))),
        (Some(_), false, _) => Ok(Err(membership(format!(
            "only a case-bound entry names a case, and this is a {} entry",
            proposal.class.name().unwrap_or("?")
        )))),
        (None, _, true) => Err(KernelError::Corrupt(
            "a case's Post admitted an entry that names no case".into(),
        )),
        (None, false, false) => Ok(Ok(None)),
    }
}

/// What the posting law decides a case member's row over: the case's
/// approvals, bound to its manifest digest, and the planners of its
/// entries (the `case_preparer` exclusion).
pub(crate) struct MemberGate {
    pub approvals: Vec<fa_model::ApprovalRef>,
    pub digest: [u8; 32],
    pub preparers: std::collections::BTreeSet<VId>,
}

/// Admit `proposal` as `member` of its case inside `txn`: the case is
/// Approved (a point witness of its state), the claimed Plan record is in
/// its approved manifest with the same intent digest, and `proposal` is
/// exactly the kernel's derivation of that entry for its principal. A
/// Revision case's entry posts in a period the case affects (`period`,
/// the one the posting law resolved).
pub(crate) fn admit_member<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    book: &BookContext,
    proposal: &EntryPayload,
    member: CaseMember,
    period: &str,
) -> Outcome<MemberGate> {
    let vid = restatement_case_vid(book.book_id, member.ordinal);
    let Some(row) = txn.vertex(db, vid)? else {
        return Ok(Err(unknown(member.ordinal)));
    };
    let state = CaseState::from_scalar(prop(&row, property::STATE)).ok_or_else(|| {
        KernelError::Corrupt(format!("restatement case {} state mirror", member.ordinal))
    })?;
    if state != CaseState::Approved {
        return Ok(Err(wrong_state(member.ordinal, state, "Post", "Approved")));
    }
    let Some(view) = read_case(db, book, member.ordinal)? else {
        return Ok(Err(unknown(member.ordinal)));
    };
    if view.body.kind == CaseKind::Revision && !view.body.periods.iter().any(|p| p == period) {
        return Ok(Err(membership(format!(
            "a Revision posts in a period its case affects, and case {} affects {}, not {period}",
            member.ordinal,
            view.body.periods.join(", ")
        ))
        .at("period", period)));
    }
    let (Some(approval), Some(rehearsal)) = (view.approval.as_ref(), view.rehearsal.as_ref())
    else {
        return Err(KernelError::Corrupt(format!(
            "approved case {} carries no approval or rehearsal record",
            member.ordinal
        )));
    };
    let Some(entry) = approval
        .manifest
        .entries
        .iter()
        .find(|e| e.plan == member.plan)
    else {
        return Ok(Err(membership(format!(
            "Plan record {:032x} is not in case {}'s approved manifest",
            member.plan.0, member.ordinal
        ))));
    };
    let planned = crate::scenario::read_scenario(db, book, &rehearsal.scenario)?
        .and_then(|s| s.intents.into_iter().find(|p| p.record == member.plan))
        .ok_or_else(|| {
            KernelError::Corrupt(format!(
                "case {}'s Plan record {:032x} is not in scenario `{}`",
                member.ordinal, member.plan.0, rehearsal.scenario
            ))
        })?;
    let intent = planned
        .intent
        .canonical_bytes()
        .map_err(|e| KernelError::Corrupt(format!("case manifest intent: {e}")))?;
    if domain_digest(MANIFEST_ENTRY_DOMAIN, &[&intent]) != entry.intent {
        return Err(KernelError::Corrupt(format!(
            "case {}'s Plan record {:032x} no longer has its approved intent",
            member.ordinal, member.plan.0
        )));
    }
    let derived = match derive_member(
        book.book_id,
        view.body.kind,
        member.ordinal,
        member.plan,
        planned.intent.proposal(),
        proposal.principal_ref,
    )? {
        Ok(derived) => derived,
        Err(r) => return Ok(Err(r)),
    };
    if derived.proposal_digest()? != proposal.proposal_digest()? {
        return Ok(Err(membership(format!(
            "this entry is not case {}'s derivation of Plan record {:032x}; post the case with `fa case post {}`",
            member.ordinal, member.plan.0, member.ordinal
        ))));
    }
    Ok(Ok(MemberGate {
        approvals: approval.approvals.clone(),
        digest: approval.manifest.digest()?,
        preparers: approval.manifest.preparers(),
    }))
}

/// The entries case `ordinal` posts under `principal`, in manifest order.
fn case_members<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    view: &CaseView,
    principal: VId,
) -> Outcome<Vec<(VId, EntryPayload)>> {
    let ordinal = view.body.ordinal;
    let (Some(approval), Some(rehearsal)) = (view.approval.as_ref(), view.rehearsal.as_ref())
    else {
        return Ok(Err(wrong_state(ordinal, view.state, "Post", "Approved")));
    };
    if approval.manifest.entries.is_empty() {
        return Ok(Err(membership(format!(
            "case {ordinal}'s approved manifest names no entry: there is nothing to post"
        ))));
    }
    let Some(scenario) = crate::scenario::read_scenario(db, book, &rehearsal.scenario)? else {
        return Ok(Err(rehearsal_refused(format!(
            "case {ordinal}'s scenario `{}` is not in this book",
            rehearsal.scenario
        ))));
    };
    let mut out = Vec::with_capacity(approval.manifest.entries.len());
    for entry in &approval.manifest.entries {
        let Some(planned) = scenario.intents.iter().find(|p| p.record == entry.plan) else {
            return Err(KernelError::Corrupt(format!(
                "case {ordinal}'s Plan record {:032x} is not in its scenario",
                entry.plan.0
            )));
        };
        match derive_member(
            book.book_id,
            view.body.kind,
            ordinal,
            entry.plan,
            planned.intent.proposal(),
            principal,
        )? {
            Ok(derived) => out.push((entry.plan, derived)),
            Err(r) => return Ok(Err(r)),
        }
    }
    Ok(Ok(out))
}

/// Post case `ordinal` (Approved → Posted) in one commit (plan §8.3): its
/// manifest's entries as one atomic batch, each through every posting law
/// under `req.capability` (its own matrix row and SoD rule, decided over the
/// case's approvals), the Post record naming them, and the compare-and-set
/// of the case's `state`. An identical retry returns the recorded case.
pub async fn post_case<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    ordinal: u32,
    req: CaseRequest,
) -> Outcome<CaseRecorded> {
    const FIX: &str = "fa case post <case>";
    if ordinal == 0 {
        return Ok(Err(unknown(ordinal)));
    }
    if let Err(r) = admit(db, book, &req.capability, Act::Post)? {
        return Ok(Err(r));
    }
    let vid = restatement_case_vid(book.book_id, ordinal);
    let principal = req.capability.holder();
    let Some(view) = read_case(db, book, ordinal)? else {
        return Ok(Err(unknown(ordinal)));
    };
    let record = |entries: &[PostedEntry]| -> Result<EntryPayload, KernelError> {
        let bytes = posted_bytes(entries)?;
        Ok(record_proposal(
            book,
            &req,
            Act::Post,
            vid,
            CaseState::Approved.tag(),
            CaseState::Posted,
            entries.iter().map(|e| TypedRef::Vertex(e.entry)).collect(),
            domain_digest(POSTED_DOMAIN, &[&bytes]),
            Some((fa_model::entry::CASE_POSTED_EXTENSION, bytes)),
        ))
    };
    let evid = entry_vid(
        book.book_id,
        &principal.0.to_le_bytes(),
        &record_key(Act::Post, Some(vid), &req.idempotency_key),
    );
    if view.state == CaseState::Posted {
        let proposal = record(&view.posted)?;
        return Ok(match db.vertex(evid)? {
            Some(row) => match recorded_or_conflict(book, &row, &proposal)? {
                Ok(recorded_at) => Ok(CaseRecorded {
                    case: view,
                    control_entry: evid,
                    recorded_at,
                    already_recorded: true,
                }),
                Err(r) => Err(r),
            },
            None => Err(wrong_state(ordinal, view.state, "Post", "Approved")),
        });
    }
    if view.state != CaseState::Approved {
        return Ok(Err(wrong_state(ordinal, view.state, "Post", "Approved")));
    }
    let members = match case_members(db, book, &view, principal)? {
        Ok(members) => members,
        Err(r) => return Ok(Err(r)),
    };
    let intents = members
        .iter()
        .map(|(_, proposal)| fa_intents::PostIntent::new(proposal.clone(), Vec::new()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| KernelError::Corrupt(format!("case post intent: {e}")))?;
    let batch_key = domain_digest(POST_BATCH_KEY_DOMAIN, &[&vid.0.to_le_bytes()]).to_vec();
    let batch = fa_intents::PostBatch::new(batch_key, intents)
        .map_err(|e| KernelError::Corrupt(format!("case post batch: {e}")))?;
    let admission = crate::post::Admission::Case(Posting(()));
    if let Err(r) = crate::batch::authorize_members(db, book, &req.capability, &batch, admission)? {
        return Ok(Err(r));
    }
    ctx.query()
        .checkpoint()
        .map_err(WriteTxnError::Interrupted)?;
    if let Err(r) = crate::scratch::ensure_history(db, ctx).await? {
        return Ok(Err(r));
    }
    let capabilities = vec![req.capability.clone(); batch.members().len()];
    let mut staged =
        match crate::batch::stage_batch(db, ctx, book, &capabilities, &batch, admission)? {
            Err(r) => return Ok(Err(r)),
            // The identical request committed after this read the case:
            // retrying returns its recorded case.
            Ok(crate::batch::BatchStage::Recorded(_)) => {
                return Ok(Err(fcw("the case's entries committed concurrently")));
            }
            Ok(crate::batch::BatchStage::Staged(staged)) => staged,
        };
    if let Err(r) = capability_witness(&staged.txn, db, book, &req.capability)? {
        staged.txn.abort();
        return Ok(Err(r));
    }
    let entries: Vec<PostedEntry> = members
        .iter()
        .zip(&staged.entries)
        .map(|((plan, _), entry)| PostedEntry {
            plan: *plan,
            entry: entry.vid,
            entry_digest: entry.entry_digest,
        })
        .collect();
    let proposal = record(&entries)?;
    // Every member point-read the case as Approved in this transaction, so
    // its Post record cannot exist here.
    if staged.txn.vertex(db, evid)?.is_some() {
        staged.txn.abort();
        return Err(KernelError::Corrupt(format!(
            "case {ordinal} is Approved but its Post record already exists"
        )));
    }
    if proposal.validate().is_err() {
        staged.txn.abort();
        return Ok(Err(usage(
            "the Post record is not a valid CaseControl entry",
            FIX,
        )));
    }
    let entry = proposal.seal(Vec::new(), None)?;
    let mut in_case = WriteBatch::new(relation::IN_CASE);
    in_case.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    in_case.compare_and_set_vertex_property(
        vid,
        property::STATE,
        Some(CaseState::Approved.scalar()),
        CaseState::Posted.scalar(),
        WriteMismatchPolicy::AbortWrite,
    );
    in_case.add_edge(edge_id(relation::IN_CASE, evid, vid), evid, vid, vec![]);
    for e in &entries {
        in_case.add_edge(
            edge_id(relation::IN_CASE, e.entry, vid),
            e.entry,
            vid,
            vec![],
        );
    }
    staged.txn.write(db, in_case)?;
    if let Err(d) = fa_policy::current(&req.capability, db.frontier()?) {
        staged.txn.abort();
        return Ok(Err(denial(&d)));
    }
    let posted =
        match crate::batch::commit_batch(db, ctx, book, &capabilities, &batch, admission, staged)
            .await?
        {
            Err(r) => return Ok(Err(r)),
            Ok(posted) => posted,
        };
    if posted.already_recorded {
        return Ok(Err(fcw("the case's entries committed concurrently")));
    }
    Ok(Ok(CaseRecorded {
        case: read_case(db, book, ordinal)?
            .ok_or_else(|| KernelError::Corrupt(format!("case {ordinal} vanished")))?,
        control_entry: evid,
        recorded_at: posted.recorded_at,
        already_recorded: false,
    }))
}

/// A case's disclosure (extension 25): the Disclosure document it is
/// disclosed in and the Reviewed attestation over that document.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Disclosure {
    pub document: Oid,
    pub attestation: VId,
}

impl Disclosure {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, KernelError> {
        let mut w = Writer::with_capacity(52);
        w.u16(DISCLOSURE_VERSION)
            .fixed(&self.document.0)
            .u128(self.attestation.0);
        Ok(w.finish()?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, KernelError> {
        let mut r = Reader::new(bytes);
        if r.u16("case.disclosure.version").map_err(decode)? != DISCLOSURE_VERSION {
            return Err(KernelError::Corrupt(
                "unsupported case disclosure version".into(),
            ));
        }
        let disclosure = Self {
            document: Oid(r.fixed("case.disclosure.document").map_err(decode)?),
            attestation: VId(r.u128("case.disclosure.attestation").map_err(decode)?),
        };
        r.finish().map_err(decode)?;
        Ok(disclosure)
    }
}

fn disclosure_refused(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::CASE_DISCLOSURE,
        exit::REFUSAL,
        message.into(),
        "plan §8.3 (Disclosed: the disclosure document is attested), §9.3",
        "record the disclosure with `fa document add <file> --kind Disclosure`, have a principal other than its uploader attest it with `fa attest review <oid>`, then `fa case disclose <case> --document <oid>`",
    )
}

/// Inside `txn`: `disclosure` names a verified Disclosure document of this
/// book and the Reviewed attestation over it (its identity is derived from
/// the document, plan §9.3), both read as point witnesses.
fn witness_disclosure<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    book: &BookContext,
    disclosure: &Disclosure,
) -> Outcome<()> {
    let oid = &disclosure.document;
    let record = match witness_document(txn, db, oid, "disclosure")? {
        Ok(record) => record,
        Err(r) => return Ok(Err(r)),
    };
    let policy = EvidencePolicy::embedded().map_err(|e| KernelError::Corrupt(e.to_string()))?;
    let kind = policy.kind_by_name("Disclosure").ok_or_else(|| {
        KernelError::Corrupt("evidence_policy.toml registers no Disclosure kind".into())
    })?;
    if record.kind != kind.tag {
        return Ok(Err(disclosure_refused(format!(
            "document {} is a {}, not a Disclosure",
            hex(&oid.0),
            policy
                .kind_by_tag(record.kind)
                .map_or("unregistered kind", |k| k.name.as_str())
        ))));
    }
    match crate::attestation::witness_review(txn, db, book.book_id, oid)? {
        Ok(Some(review)) if review.attestation == disclosure.attestation => Ok(Ok(())),
        Ok(Some(_)) => Err(KernelError::Corrupt(format!(
            "the review of document {} is not at its derived identity",
            hex(&oid.0)
        ))),
        Ok(None) => Ok(Err(disclosure_refused(format!(
            "disclosure document {} carries no Reviewed attestation",
            hex(&oid.0)
        )))),
        Err(r) => Ok(Err(r)),
    }
}

/// Journal `proposal`, case `ordinal`'s `act` record moving it `from` →
/// `to`, in one commit after `witness` has read what the record rests on
/// inside the transaction. The identical record is its recorded outcome.
#[allow(clippy::too_many_arguments)]
async fn transition<V, W>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    req: &CaseRequest,
    ordinal: u32,
    act: Act,
    (from, to): (CaseState, CaseState),
    proposal: EntryPayload,
    witness: W,
) -> Outcome<CaseRecorded>
where
    V: asupersync::fs::Vfs + Clone,
    W: FnOnce(&WriteTxn, &Database<V>) -> Outcome<()>,
{
    let vid = restatement_case_vid(book.book_id, ordinal);
    let evid = entry_vid(
        book.book_id,
        &req.capability.holder().0.to_le_bytes(),
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
    if state != from {
        txn.abort();
        return Ok(Err(wrong_state(
            ordinal,
            state,
            act.transition(),
            from.name(),
        )));
    }
    if let Err(r) = witness(&txn, &*db)? {
        txn.abort();
        return Ok(Err(r));
    }
    if proposal.validate().is_err() {
        txn.abort();
        return Ok(Err(usage(
            format!(
                "the {} record is not a valid CaseControl entry",
                act.transition()
            ),
            "fa case show <case> --json",
        )));
    }
    let entry = proposal.seal(Vec::new(), None)?;
    let mut batch = WriteBatch::new(relation::IN_CASE);
    batch.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    batch.compare_and_set_vertex_property(
        vid,
        property::STATE,
        Some(from.scalar()),
        to.scalar(),
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

/// Disclose case `ordinal` (Posted → Disclosed) in `document`: a Disclosure
/// document of this book that a principal other than its uploader has
/// reviewed (plan §8.3 "the disclosure document is attested").
pub async fn disclose_case<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    ordinal: u32,
    document: Oid,
    req: CaseRequest,
) -> Outcome<CaseRecorded> {
    if ordinal == 0 {
        return Ok(Err(unknown(ordinal)));
    }
    if let Err(r) = admit(db, book, &req.capability, Act::Disclose)? {
        return Ok(Err(r));
    }
    let disclosure = Disclosure {
        document,
        attestation: crate::attestation::review_vid(book.book_id, &document),
    };
    let bytes = disclosure.canonical_bytes()?;
    let proposal = record_proposal(
        book,
        &req,
        Act::Disclose,
        restatement_case_vid(book.book_id, ordinal),
        CaseState::Posted.tag(),
        CaseState::Disclosed,
        vec![
            TypedRef::Object(disclosure.document),
            TypedRef::Vertex(disclosure.attestation),
        ],
        domain_digest(DISCLOSURE_DOMAIN, &[&bytes]),
        Some((fa_model::entry::CASE_DISCLOSURE_EXTENSION, bytes)),
    );
    transition(
        db,
        ctx,
        book,
        &req,
        ordinal,
        Act::Disclose,
        (CaseState::Posted, CaseState::Disclosed),
        proposal,
        |txn, db| witness_disclosure(txn, db, book, &disclosure),
    )
    .await
}

/// Close case `ordinal` (Disclosed → Closed): its last record.
pub async fn close_case<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    ordinal: u32,
    req: CaseRequest,
) -> Outcome<CaseRecorded> {
    if ordinal == 0 {
        return Ok(Err(unknown(ordinal)));
    }
    if let Err(r) = admit(db, book, &req.capability, Act::Close)? {
        return Ok(Err(r));
    }
    let vid = restatement_case_vid(book.book_id, ordinal);
    let proposal = record_proposal(
        book,
        &req,
        Act::Close,
        vid,
        CaseState::Disclosed.tag(),
        CaseState::Closed,
        Vec::new(),
        domain_digest(CLOSE_DOMAIN, &[&vid.0.to_le_bytes()]),
        None,
    );
    transition(
        db,
        ctx,
        book,
        &req,
        ordinal,
        Act::Close,
        (CaseState::Disclosed, CaseState::Closed),
        proposal,
        |_, _| Ok(Ok(())),
    )
    .await
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
    let mut approval = None;
    let mut posted = Vec::new();
    let mut disclosure = None;
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
        if let Some((_, ext)) = entry
            .proposal
            .extensions
            .iter()
            .find(|(tag, _)| *tag == fa_model::entry::CASE_APPROVAL_EXTENSION)
        {
            approval = Some(CaseApproval {
                manifest: CaseManifest::decode(ext)?,
                approvals: entry.approvals.clone(),
            });
        }
        if let Some((_, ext)) = entry
            .proposal
            .extensions
            .iter()
            .find(|(tag, _)| *tag == fa_model::entry::CASE_POSTED_EXTENSION)
        {
            posted = decode_posted(ext)?;
        }
        if let Some((_, ext)) = entry
            .proposal
            .extensions
            .iter()
            .find(|(tag, _)| *tag == fa_model::entry::CASE_DISCLOSURE_EXTENSION)
        {
            disclosure = Some(Disclosure::decode(ext)?);
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
        approval,
        posted,
        disclosure,
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
    fn a_manifest_round_trips_and_names_its_planners() {
        let manifest = CaseManifest {
            case: VId(7),
            body_digest: [1; 32],
            rehearsal_digest: [2; 32],
            entries: vec![
                ManifestEntry {
                    plan: VId(10),
                    intent: [3; 32],
                    planner: VId(4),
                },
                ManifestEntry {
                    plan: VId(11),
                    intent: [5; 32],
                    planner: VId(4),
                },
            ],
        };
        let bytes = manifest.canonical_bytes().unwrap();
        assert_eq!(CaseManifest::decode(&bytes).unwrap(), manifest);
        assert_eq!(
            manifest.preparers().into_iter().collect::<Vec<_>>(),
            [VId(4)]
        );
        let mut reordered = manifest.clone();
        reordered.entries.reverse();
        assert_ne!(
            reordered.digest().unwrap(),
            manifest.digest().unwrap(),
            "order is bound"
        );
        let mut trailing = bytes;
        trailing.push(0);
        assert!(CaseManifest::decode(&trailing).is_err());
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
