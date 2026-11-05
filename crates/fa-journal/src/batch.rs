//! Atomic batches (plan §5.8–5.9, bead fa-nl7): an ordered list of PostEntry
//! intents committed in one substrate transaction, all or none, in order,
//! each member seeing every earlier member's staged effects, together with a
//! key-derived immutable `IntentOutcome` that records the committed outcome.
//!
//! Every member runs the production posting pipeline ([`crate::post`]):
//! admission, period law, SoD, evidence minimum, the balance law, limits and
//! application law are each judged member by member, against the book as
//! the earlier members leave it. A member refusal refuses the batch: the
//! refusal names the member, and nothing is staged. The commit is the one
//! substrate transaction, validated by first-committer-wins over every
//! member's witnesses, so a batch is never half-recorded.
//!
//! The outcome's identity derives from the batch key under the members'
//! common principal, so an identical retry, after a lost response, returns
//! the recorded outcome. The same key with different members or order is an
//! idempotency conflict. Recording durable refusals as outcomes (the rest
//! of the FA-INV-09 `intent-outcome` clause) is not part of this slice.

use std::collections::BTreeSet;

use asupersync::fs::Vfs;
use fa_intents::{BatchPlan, BatchPlanCertificate, PostBatch};
use fa_model::symbols::{label, property, relation};
use fa_model::{Entry, EntryClass, EntryRef, Id128, Reader, Writer, intent_outcome_vid};
use fa_policy::Capability;
use fgdb::{Database, VertexRow, WriteBatch, WriteTxn, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, QueryCx, VId};

use crate::genesis::BookContext;
use crate::object::{self, ObjectKind};
use crate::policy;
use crate::post::{Admission, BatchMember, PostPreparation, PostRequest, prepare_member};
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{edge_id, prop, scalar_bytes};

const OUTCOME_MAGIC: &[u8; 11] = b"FA-OUTCOME\0";
const OUTCOME_MAJOR: u16 = 1;
const OUTCOME_MINOR: u16 = 0;
/// The outcome kind of a committed PostBatch.
const KIND_BATCH: u8 = 1;
/// Header and count framing plus the maximum ordered list of EntryRefs.
pub const MAX_OUTCOME_BYTES: usize = 52 + 48 * fa_model::limits::MAX_BATCH_ENTRIES;

/// A verified batch artifact satisfies an explicit `requires_dry_run`
/// caveat without adding a circular certificate digest to its entry bytes.
/// Only this module can construct the token, after authenticating the full
/// plan and its exact caller capability. It grants no trunk authority.
#[derive(Clone, Copy, Debug)]
pub(crate) struct VerifiedBatchPlan(());

/// The existing single-item carrying law composes only when no member can
/// change another member's source. This token admits the complete batch's
/// shape and execution posture; fresh preparation also checks source and
/// valuation account isolation before staging the outcome or publishing.
#[derive(Clone, Copy, Debug)]
pub(crate) struct IndependentCarryingBatch(());

/// Each lot fold reads only its governed account. This token proves that
/// every member's effects leave every other member's source unchanged.
/// The complete committed prefix remains guarded through publication.
#[derive(Clone, Copy, Debug)]
pub(crate) struct IndependentDisposalBatch(());

/// Every charge names a different immutable acquisition and schedule. No
/// member changes another member's recognized-cost state or source guard.
/// Only this module constructs the proof after admitting every planner.
#[derive(Clone, Copy, Debug)]
pub(crate) struct IndependentAssetChargeBatch(());

/// Only this module proves that the complete draft consists of one intrinsic
/// Closing. The planner keeps its own authority; promotion additionally
/// requires the draft factory's explicit Close-authorized promoter token.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SingletonClosingDraft(());

/// Only a complete, singleton case batch can carry this proof. It delegates
/// no authority: the member's own Locked row still requires Restate and the
/// case's dual approval, and its original source guard survives publication.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SingletonCaseClosing(());

/// A source-bound revaluation can be rehearsed and promoted only as the
/// complete draft's one intrinsic effect. No sibling can change its source.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SingletonRevaluationDraft(());

/// The complete batch's private source-composition proofs travel together
/// through preparation and publication. An empty set grants no exception.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct AggregateProofs {
    pub(crate) carrying: Option<IndependentCarryingBatch>,
    pub(crate) disposal: Option<IndependentDisposalBatch>,
    pub(crate) asset_charge: Option<IndependentAssetChargeBatch>,
    pub(crate) closing: Option<SingletonClosingDraft>,
    pub(crate) case_closing: Option<SingletonCaseClosing>,
    pub(crate) revaluation: Option<SingletonRevaluationDraft>,
}

pub(crate) struct MemberPreparation {
    pub(crate) txn: Option<WriteTxn>,
    pub(crate) proofs: AggregateProofs,
}

fn singleton_closing_draft(
    batch: &PostBatch,
    admission: Admission,
) -> Result<Option<SingletonClosingDraft>, Refusal> {
    if !matches!(
        admission,
        Admission::PlanDraft(_) | Admission::Promote(_) | Admission::ScratchDraft(_)
    ) || !batch.members().iter().any(|member| {
        member.proposal().class == EntryClass::CLOSING
            || member
                .proposal()
                .extensions
                .iter()
                .any(|(tag, _)| *tag == fa_model::entry::YEAR_END_CLOSE_EXTENSION)
    }) {
        return Ok(None);
    }
    if batch.members().len() != 1
        || matches!(admission, Admission::Promote(token) if !token.authorizes_closing())
    {
        return Err(crate::closing::draft_scope_refusal());
    }
    if crate::closing::admit(batch.members()[0].proposal())?.is_none() {
        return Err(crate::closing::draft_scope_refusal());
    }
    Ok(Some(SingletonClosingDraft(())))
}

fn singleton_case_closing(
    batch: &PostBatch,
    admission: Admission,
) -> Result<Option<SingletonCaseClosing>, Refusal> {
    if !matches!(admission, Admission::Case(_))
        || !batch.members().iter().any(|member| {
            member.proposal().class == EntryClass::CLOSING
                || member
                    .proposal()
                    .extensions
                    .iter()
                    .any(|(tag, _)| *tag == fa_model::entry::YEAR_END_CLOSE_EXTENSION)
        })
    {
        return Ok(None);
    }
    if batch.members().len() != 1
        || crate::closing::admit(batch.members()[0].proposal())?.is_none()
        || !batch.members()[0]
            .proposal()
            .extensions
            .iter()
            .any(|(tag, _)| *tag == fa_model::entry::CASE_MEMBER_EXTENSION)
    {
        return Err(crate::closing::case_scope_refusal());
    }
    Ok(Some(SingletonCaseClosing(())))
}

fn singleton_revaluation_draft(
    batch: &PostBatch,
    admission: Admission,
) -> Result<Option<SingletonRevaluationDraft>, Refusal> {
    if !matches!(
        admission,
        Admission::PlanDraft(_) | Admission::Promote(_) | Admission::ScratchDraft(_)
    ) || !batch.members().iter().any(|member| {
        member.proposal().class == EntryClass::REVALUATION
            || crate::revaluation::is_source_bound(member.proposal())
    }) {
        return Ok(None);
    }
    if batch.members().len() != 1
        || batch.members()[0].proposal().class != EntryClass::REVALUATION
        || crate::revaluation::admit(batch.members()[0].proposal())?.is_none()
    {
        return Err(crate::revaluation::unsupported_batch());
    }
    Ok(Some(SingletonRevaluationDraft(())))
}

fn independent_carrying_batch(
    batch: &PostBatch,
    admission: Admission,
) -> Outcome<Option<IndependentCarryingBatch>> {
    if !batch
        .members()
        .iter()
        .any(|member| crate::carrying::is_source_bound(member.proposal()))
    {
        return Ok(Ok(None));
    }
    if !matches!(
        admission,
        Admission::Commit
            | Admission::Plan
            | Admission::PlanDraft(_)
            | Admission::VerifiedBatch(_)
            | Admission::Promote(_)
            | Admission::ScratchDraft(_)
    ) {
        return Ok(Err(crate::carrying::unsupported_batch()));
    }
    let mut targets = BTreeSet::new();
    for (index, member) in batch.members().iter().enumerate() {
        let proposal = member.proposal();
        if !crate::carrying::is_source_bound(proposal) {
            // Ordinary companions cannot change target liveness, apply to
            // an open item, or add another committed-prefix derivation.
            // Their account isolation is checked after native admission.
            if proposal.class != EntryClass::ORIGINAL
                || !proposal.supersession.is_empty()
                || proposal.pending.is_some()
                || proposal.control.is_some()
                || proposal.legs.iter().any(|leg| !leg.settles.is_empty())
                || crate::post::requires_aggregate_basis(proposal)?
            {
                return Ok(Err(member_refusal(
                    index,
                    crate::carrying::unsupported_batch(),
                )));
            }
            continue;
        }
        if !matches!(proposal.class, EntryClass::ORIGINAL | EntryClass::ADJUSTING) {
            return Ok(Err(member_refusal(
                index,
                crate::carrying::unsupported_batch(),
            )));
        }
        let applications: Option<Vec<_>> = member
            .proposal()
            .legs
            .iter()
            .filter(|leg| !leg.settles.is_empty())
            .map(|leg| match leg.settles.as_slice() {
                [application] => Some(application),
                _ => None,
            })
            .collect();
        let Some(applications) = applications.filter(|items| !items.is_empty()) else {
            return Ok(Err(member_refusal(
                index,
                Refusal::new(
                    code::SETTLE_SHAPE,
                    exit::REFUSAL,
                    "each atomic FX member requires one or more single-target applying legs",
                    "plan §5.7–5.10 (independent carrying-value sources)",
                    "prepare each member through the single-item or independent-group FX settlement law",
                ),
            )));
        };
        // Identity includes the ordinal, not the caller-supplied digest.
        // Independence spans every component, including grouped members.
        for application in applications {
            if !targets.insert((application.target.vid, application.ordinal)) {
                return Ok(Err(member_refusal(
                    index,
                    Refusal::new(
                        code::SETTLE_SHAPE,
                        exit::REFUSAL,
                        "atomic FX settlements require distinct existing target legs",
                        "plan §5.7–5.10 (independent carrying-value sources)",
                        "combine no two applications to the same target leg in one batch; prepare later relief after the earlier publication",
                    ),
                )));
            }
        }
    }
    Ok(Ok(Some(IndependentCarryingBatch(()))))
}

/// Complete the carrying proof only after every member passed native
/// preparation, including FX source authority. Recorded retries return
/// their existing outcome before this fresh-prefix inspection.
fn admit_carrying_batch_accounts<V: Vfs + Clone>(
    db: &Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    entries: &[Entry],
    at: CommitSeq,
) -> Outcome<()> {
    ctx.query()
        .checkpoint()
        .map_err(WriteTxnError::Interrupted)?;
    let sources: BTreeSet<_> = entries
        .iter()
        .filter(|entry| crate::carrying::is_source_bound(&entry.proposal))
        .flat_map(|entry| &entry.proposal.legs)
        .filter(|leg| !leg.settles.is_empty())
        .map(|leg| leg.account_ref)
        .collect();
    let chart = crate::chart::read_at(db, book, at)?;
    // Carrying replay protects every retained route epoch, including a
    // future-effective declaration. Selecting only today's map would let
    // a companion poison an already dedicated valuation leaf.
    let routes: Vec<_> = chart
        .fx_revaluation_routes()
        .iter()
        .flat_map(|epoch| &epoch.routes)
        .filter(|(source, _)| sources.contains(*source))
        .collect();
    for (index, entry) in entries.iter().enumerate() {
        let proposal = &entry.proposal;
        let foreign = crate::carrying::is_source_bound(proposal);
        if foreign && crate::carrying::has_allocated_basis(proposal) {
            // Exact allocated releases may share a valuation leaf across
            // distinct targets. Cash and realized offsets may not use it.
            for (source, route) in &routes {
                if let Err(refusal) =
                    crate::carrying::covers_valuation_account(proposal, **source, route)
                {
                    return Ok(Err(member_refusal(index, refusal)));
                }
            }
        } else if proposal.legs.iter().any(|leg| {
            (!foreign && sources.contains(&leg.account_ref))
                || routes
                    .iter()
                    .any(|(_, route)| route.valuation_account == leg.account_ref)
        }) {
            return Ok(Err(member_refusal(
                index,
                Refusal::new(
                    code::SETTLE_SHAPE,
                    exit::REFUSAL,
                    "atomic FX companions cannot post to a carried source or valuation account outside an exact allocated release",
                    "plan §5.7–5.10 (independent carrying-value sources)",
                    "keep ordinary postings outside the participating source and valuation accounts, and use the prepared allocated release for valuation relief",
                ),
            )));
        }
    }
    Ok(Ok(()))
}

/// A committed-prefix lot derivation composes only if no earlier member
/// can change its account's acquisitions, applications or policy. Native
/// Original disposals cannot change policy or reversal liveness; distinct
/// source accounts and disjoint source/offset effects establish the rest.
/// Shared offsets outside this source set still use ordinary staged witnesses.
fn independent_disposal_batch(
    batch: &PostBatch,
    admission: Admission,
) -> Result<Option<IndependentDisposalBatch>, Refusal> {
    if !batch
        .members()
        .iter()
        .any(|member| crate::disposal::has_basis(member.proposal()))
    {
        return Ok(None);
    }
    if !matches!(
        admission,
        Admission::Commit
            | Admission::Plan
            | Admission::PlanDraft(_)
            | Admission::VerifiedBatch(_)
            | Admission::Promote(_)
            | Admission::ScratchDraft(_)
    ) || batch.members().iter().any(|member| {
        member.proposal().class != EntryClass::ORIGINAL
            || !crate::disposal::has_basis(member.proposal())
    }) {
        return Err(crate::disposal::unsupported_batch());
    }
    let invalid = |index, message: String| {
        member_refusal(
            index,
            Refusal::new(
                code::SETTLE_SHAPE,
                exit::REFUSAL,
                message,
                "plan §5.8–5.10 / §6.5 (independent lot sources at one committed prefix)",
                "batch only disposals of distinct lot accounts whose offsets do not touch another member's lot account; prepare dependent relief after the earlier publication",
            ),
        )
    };
    let mut sources = BTreeSet::new();
    let mut bases = Vec::with_capacity(batch.members().len());
    for (index, member) in batch.members().iter().enumerate() {
        let basis = member
            .proposal()
            .lot_disposal_basis()
            .map_err(|error| invalid(index, error.to_string()))?
            .ok_or_else(|| invalid(index, "a disposal member has no lot basis".into()))?;
        // Account identity, not a supplied policy digest or a quantity unit,
        // is the dependency: FIFO and pooled cost can span multiple layers.
        if !sources.insert(basis.account) {
            return Err(invalid(
                index,
                "atomic lot disposals require distinct governed source accounts".into(),
            ));
        }
        bases.push(basis);
    }
    for (index, (member, basis)) in batch.members().iter().zip(&bases).enumerate() {
        let touches_another_source =
            |account: VId| account != basis.account && sources.contains(&account);
        if touches_another_source(basis.quantity_offset_account)
            || touches_another_source(basis.cost_offset_account)
            || member
                .proposal()
                .legs
                .iter()
                .any(|leg| touches_another_source(leg.account_ref))
        {
            return Err(invalid(
                index,
                "a lot disposal's effects or offsets touch another batch member's source account"
                    .into(),
            ));
        }
    }
    Ok(Some(IndependentDisposalBatch(())))
}

/// Schedule amounts depend on their own immutable acquisition and charge
/// history, not a GL account balance. Shared expense/accumulated accounts are
/// therefore safe; shared acquisition entries are not, because their source
/// guard records the last schedule or charge for that complete acquisition.
fn independent_asset_charge_batch<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    capabilities: &[Capability],
    batch: &PostBatch,
    admission: Admission,
) -> Outcome<Option<IndependentAssetChargeBatch>> {
    if !batch
        .members()
        .iter()
        .any(|member| crate::asset_cost::has_basis(member.proposal()))
    {
        return Ok(Ok(None));
    }
    if !matches!(
        admission,
        Admission::Commit
            | Admission::Plan
            | Admission::PlanDraft(_)
            | Admission::VerifiedBatch(_)
            | Admission::Promote(_)
            | Admission::ScratchDraft(_)
    ) || batch.members().iter().any(|member| {
        member.proposal().class != EntryClass::ADJUSTING
            || !crate::asset_cost::has_basis(member.proposal())
    }) {
        return Ok(Err(crate::asset_cost::unsupported_batch()));
    }
    // Source independence requires reading immutable schedules. Admit all
    // actual member capabilities first, including Agent trunk confinement,
    // whole-book Read/Post, expiry and revocation, before that observation.
    for (index, (intent, capability)) in batch.members().iter().zip(capabilities).enumerate() {
        if let Err(refusal) = crate::post::authorize_request(
            db,
            book,
            &member_request(intent, capability),
            admission,
        )? {
            return Ok(Err(member_refusal(index, refusal)));
        }
        if let Err(refusal) = crate::asset_cost::authorize(db, book, capability)? {
            return Ok(Err(member_refusal(index, refusal)));
        }
    }
    let mut schedules = BTreeSet::new();
    let mut acquisitions = BTreeSet::new();
    for (index, intent) in batch.members().iter().enumerate() {
        let (schedule, acquisition) =
            match crate::asset_cost::batch_source(db, book, intent.proposal())? {
                Ok(source) => source,
                Err(refusal) => return Ok(Err(member_refusal(index, refusal))),
            };
        if !schedules.insert(schedule) || !acquisitions.insert(acquisition) {
            return Ok(Err(member_refusal(
                index,
                crate::asset_cost::dependent_batch(),
            )));
        }
    }
    Ok(Ok(Some(IndependentAssetChargeBatch(()))))
}

/// The immutable body of a batch's IntentOutcome: the request it records
/// and, in member order, the entries that request committed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutcomeBody {
    /// [`request_digest`] of the recorded request: its key and its members'
    /// entry identities, in order.
    pub request_digest: [u8; 32],
    pub entries: Vec<EntryRef>,
}

impl OutcomeBody {
    /// `magic ‖ u16 major ‖ u16 minor ‖ u8 kind ‖ request_digest[32] ‖
    /// list(EntryRef)`.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, KernelError> {
        if self.entries.is_empty() || self.entries.len() > fa_model::limits::MAX_BATCH_ENTRIES {
            return Err(KernelError::Corrupt(
                "intent outcome member count is outside its format bound".into(),
            ));
        }
        let mut w = Writer::new();
        w.fixed(OUTCOME_MAGIC)
            .u16(OUTCOME_MAJOR)
            .u16(OUTCOME_MINOR)
            .u8(KIND_BATCH)
            .fixed(&self.request_digest)
            .list(&self.entries, |w, e| e.encode(w));
        w.finish().map_err(|e| KernelError::Model(e.into()))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, KernelError> {
        let corrupt = |what: &str| KernelError::Corrupt(format!("intent outcome: {what}"));
        if bytes.len() > MAX_OUTCOME_BYTES {
            return Err(corrupt("payload exceeds its format bound"));
        }
        let mut r = Reader::new(bytes);
        let decode = |e: fa_model::DecodeError| KernelError::Model(e.into());
        if r.fixed::<11>("outcome.magic").map_err(decode)? != *OUTCOME_MAGIC {
            return Err(corrupt("wrong magic"));
        }
        if r.u16("outcome.major").map_err(decode)? != OUTCOME_MAJOR
            || r.u16("outcome.minor").map_err(decode)? != OUTCOME_MINOR
        {
            return Err(corrupt("unsupported version"));
        }
        if r.u8("outcome.kind").map_err(decode)? != KIND_BATCH {
            return Err(corrupt("unsupported kind"));
        }
        let request_digest = r.fixed::<32>("outcome.request_digest").map_err(decode)?;
        let entries = r
            .list(
                fa_model::limits::MAX_BATCH_ENTRIES,
                "outcome.entries",
                EntryRef::decode,
            )
            .map_err(decode)?;
        r.finish().map_err(decode)?;
        if entries.is_empty() {
            return Err(corrupt("empty member list"));
        }
        Ok(Self {
            request_digest,
            entries,
        })
    }
}

/// A committed batch, or the recorded outcome an identical retry returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchPosted {
    /// The batch's IntentOutcome vertex.
    pub outcome: VId,
    /// The members' entries, in member order.
    pub entries: Vec<EntryRef>,
    /// Each member's resolved period, in member order; empty for a recorded
    /// outcome (read each entry for its period).
    pub periods: Vec<String>,
    /// The one commit that recorded every member.
    pub recorded_at: CommitSeq,
    /// True when this is an identical retry's recorded outcome: nothing new
    /// was written.
    pub already_recorded: bool,
}

/// The identity of `batch`'s IntentOutcome in `book`.
#[must_use]
pub fn outcome_vid(book: &BookContext, batch: &PostBatch) -> VId {
    intent_outcome_vid(
        book.book_id,
        &batch.principal().0.to_le_bytes(),
        batch.idempotency_key(),
    )
}

/// Read a recorded IntentOutcome.
pub fn read_outcome<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    vid: VId,
) -> Result<Option<(OutcomeBody, CommitSeq)>, KernelError> {
    cx.checkpoint().map_err(WriteTxnError::Interrupted)?;
    let at = db.frontier()?;
    db.vertex_at(vid, at)?
        .map(|row| outcome_of(db, cx, &row, at))
        .transpose()
}

fn outcome_of<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    row: &VertexRow,
    at: CommitSeq,
) -> Result<(OutcomeBody, CommitSeq), KernelError> {
    cx.checkpoint().map_err(WriteTxnError::Interrupted)?;
    if row.labels.as_slice() != [label::INTENT_OUTCOME] {
        return Err(KernelError::Corrupt(format!(
            "vertex {:032x} at an intent outcome identity is not an IntentOutcome",
            row.vid.0
        )));
    }
    let Some(CanonicalScalar::Bytes(bytes)) = crate::rows::prop(row, property::FA_PAYLOAD) else {
        return Err(KernelError::Corrupt(
            "intent outcome without _fa_payload".into(),
        ));
    };
    let body = if row.props.len() == 1 {
        // Historical outcomes used one raw scalar, including bodies above
        // the new 4096-byte inline threshold. Preserve their exact bytes.
        OutcomeBody::decode(bytes.as_slice())?
    } else if row.props.len() == 2 {
        let Some(CanonicalScalar::Bytes(book)) = prop(row, property::BOOK_ID) else {
            return Err(KernelError::Corrupt(
                "chunked outcome without book identity".into(),
            ));
        };
        let book: [u8; 16] = book.as_slice().try_into().map_err(|_| {
            KernelError::Corrupt("chunked outcome has an invalid book identity".into())
        })?;
        let bytes = object::read(
            db,
            cx,
            Id128(book),
            row,
            label::INTENT_OUTCOME,
            ObjectKind::IntentOutcome,
            at,
            MAX_OUTCOME_BYTES,
        )?;
        if bytes.len() <= object::CHUNK_BYTES
            || prop(row, property::FA_PAYLOAD)
                != Some(&scalar_bytes(
                    "intent outcome",
                    object::payload(ObjectKind::IntentOutcome, &bytes)?,
                )?)
        {
            return Err(KernelError::Corrupt("invalid chunked outcome root".into()));
        }
        OutcomeBody::decode(&bytes)?
    } else {
        return Err(KernelError::Corrupt(
            "intent outcome has unexpected properties".into(),
        ));
    };
    Ok((body, row.created_at))
}

fn opt_scalar_len(value: Option<&CanonicalScalar>) -> usize {
    match value {
        None => 1,
        Some(scalar) => 5 + scalar.canonical_encoded_len().expect("canonical scalar"),
    }
}

const fn bytes_scalar_encoded_len(raw_len: usize) -> usize {
    1 + (raw_len / 8 + 1) * 9
}

/// Exact canonical `LogicalDeltaTemplate::canonical_bytes().len()` tracker for
/// a staged substrate transaction (fa-gbkc).
///
/// Chronicle V1 capsules cap protected bytes at `MAX_PROTECTED_LEN_V1`
/// (`56_403 * 256 = 14,439,168`), minus the 16-byte AEAD tag = `14,439,152`
/// (`fa_model::limits::MAX_BATCH_TEMPLATE_BYTES`). Tracking the exact
/// canonical template footprint as batch members and control edges are staged
/// turns a commit-time foundation error (`CapsuleError::Recovery`, exit 5)
/// into a deterministic `FA-REF-201` refusal (exit 3) naming the member and
/// recommended split count before any write is published.
///
/// Totals are adjusted only for the row being changed. The per-member budget
/// check is constant-time rather than re-counting the entire staged prefix
/// (fa-q7vt). The pinned substrate retains every submitted relation coordinate,
/// including empty ones after property changes cancel or fold into a creation
/// in another coordinate. Its framing remains charged even with no net rows.
#[derive(Debug, Default)]
pub(crate) struct TemplateByteTracker {
    relations: std::collections::BTreeSet<fgdb_delta_types::RelationId>,
    row_bytes: usize,
    created_vertices: std::collections::BTreeMap<VId, CreatedVertexBytes>,
    property_updates:
        std::collections::BTreeMap<(VId, fgdb_delta_types::PropertyKeyId), PropertyUpdate>,
    undo: Option<TemplateByteUndo>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CreatedVertexBytes {
    row_bytes: usize,
    props: std::collections::BTreeMap<fgdb_delta_types::PropertyKeyId, usize>,
}

/// The original value remains the comparison basis across repeated updates.
/// A change back to that value contributes no row; its coordinate remains.
#[derive(Clone, Debug, PartialEq, Eq)]
struct PropertyUpdate {
    before: Option<CanonicalScalar>,
    before_len: usize,
    row_bytes: usize,
}

/// First-touch undo records for one speculative member. A created-row snapshot
/// copies only that row's bounded property lengths, never the staged prefix.
/// Existing property updates keep their immutable before-image in place: only
/// their previous byte contribution must be restored.
#[derive(Debug, Default)]
struct TemplateByteUndo {
    row_bytes: usize,
    new_relations: Vec<fgdb_delta_types::RelationId>,
    created_vertices: std::collections::BTreeMap<VId, Option<CreatedVertexBytes>>,
    property_updates:
        std::collections::BTreeMap<(VId, fgdb_delta_types::PropertyKeyId), Option<usize>>,
}

impl Clone for TemplateByteTracker {
    fn clone(&self) -> Self {
        // A clone is an independent snapshot, including when inspected during
        // a checkpoint; it must not inherit another tracker's rollback state.
        Self {
            relations: self.relations.clone(),
            row_bytes: self.row_bytes,
            created_vertices: self.created_vertices.clone(),
            property_updates: self.property_updates.clone(),
            undo: None,
        }
    }
}

/// A speculative member's byte accounting. Dropping the guard restores its
/// exact starting state; acceptance must explicitly call `commit`.
#[must_use = "call commit to accept the speculative member"]
pub(crate) struct TemplateByteCheckpoint<'a> {
    tracker: &'a mut TemplateByteTracker,
}

impl TemplateByteCheckpoint<'_> {
    pub(crate) fn commit(self) {
        self.tracker.undo = None;
    }
}

impl std::ops::Deref for TemplateByteCheckpoint<'_> {
    type Target = TemplateByteTracker;

    fn deref(&self) -> &Self::Target {
        self.tracker
    }
}

impl std::ops::DerefMut for TemplateByteCheckpoint<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.tracker
    }
}

impl Drop for TemplateByteCheckpoint<'_> {
    fn drop(&mut self) {
        let Some(undo) = self.tracker.undo.take() else {
            return;
        };
        for (vid, previous) in undo.created_vertices {
            match previous {
                Some(created) => {
                    self.tracker.created_vertices.insert(vid, created);
                }
                None => {
                    self.tracker.created_vertices.remove(&vid);
                }
            }
        }
        for (key, previous) in undo.property_updates {
            match previous {
                Some(row_bytes) => {
                    self.tracker
                        .property_updates
                        .get_mut(&key)
                        .expect("checkpoint preserves original property updates")
                        .row_bytes = row_bytes;
                }
                None => {
                    self.tracker.property_updates.remove(&key);
                }
            }
        }
        for relation in undo.new_relations {
            self.tracker.relations.remove(&relation);
        }
        self.tracker.row_bytes = undo.row_bytes;
    }
}

impl TemplateByteTracker {
    /// Speculate on one member without cloning the accepted prefix. Nested
    /// checkpoints are rejected before replacing the outer rollback state.
    pub(crate) fn checkpoint(&mut self) -> TemplateByteCheckpoint<'_> {
        assert!(self.undo.is_none(), "nested template byte checkpoints");
        self.undo = Some(TemplateByteUndo {
            row_bytes: self.row_bytes,
            ..TemplateByteUndo::default()
        });
        TemplateByteCheckpoint { tracker: self }
    }

    fn touch_relation(&mut self, relation: fgdb_delta_types::RelationId) {
        if self.relations.insert(relation)
            && let Some(undo) = &mut self.undo
        {
            undo.new_relations.push(relation);
        }
    }

    fn add_row(&mut self, relation: fgdb_delta_types::RelationId, bytes: usize) {
        self.touch_relation(relation);
        self.row_bytes += bytes;
    }

    pub(crate) fn create_vertex(
        &mut self,
        relation: fgdb_delta_types::RelationId,
        vid: VId,
        labels_len: usize,
        props: &[(fgdb_delta_types::PropertyKeyId, CanonicalScalar)],
    ) {
        self.create_vertex_lens(
            relation,
            vid,
            labels_len,
            props
                .iter()
                .map(|(k, v)| (*k, v.canonical_encoded_len().expect("canonical scalar"))),
        );
    }

    pub(crate) fn create_vertex_lens(
        &mut self,
        relation: fgdb_delta_types::RelationId,
        vid: VId,
        labels_len: usize,
        props: impl IntoIterator<Item = (fgdb_delta_types::PropertyKeyId, usize)>,
    ) {
        let props: std::collections::BTreeMap<_, _> = props.into_iter().collect();
        let row_bytes = 38 + 8 * labels_len + props.values().map(|len| 12 + len).sum::<usize>();
        if let Some(undo) = &mut self.undo {
            undo.created_vertices
                .entry(vid)
                .or_insert_with(|| self.created_vertices.get(&vid).cloned());
        }
        let previous = self
            .created_vertices
            .insert(vid, CreatedVertexBytes { row_bytes, props });
        if let Some(previous) = previous {
            self.row_bytes -= previous.row_bytes;
        }
        self.add_row(relation, row_bytes);
    }

    pub(crate) fn record_entry_outcome_claim(
        &mut self,
        relation: fgdb_delta_types::RelationId,
        proposal: &fa_model::EntryPayload,
    ) {
        if crate::outcome::covered_class(proposal.class) {
            let ovid = crate::outcome::entry_outcome_vid(proposal);
            self.create_vertex_lens(
                relation,
                ovid,
                1,
                [
                    (property::FA_PAYLOAD, bytes_scalar_encoded_len(134)),
                    (property::TARGET_REF, bytes_scalar_encoded_len(16)),
                ],
            );
        }
    }

    pub(crate) fn record_external_subledger(
        &mut self,
        relation: fgdb_delta_types::RelationId,
        batch: &crate::external_subledger::ExternalSubledgerBatch,
    ) {
        let payload_len = 168 + batch.feed.len() + batch.batch_key.len();
        self.create_vertex_lens(
            relation,
            batch.identity(),
            1,
            [
                (property::FA_DIGEST, bytes_scalar_encoded_len(32)),
                (property::FA_PAYLOAD, bytes_scalar_encoded_len(payload_len)),
                (property::BOOK_ID, bytes_scalar_encoded_len(16)),
                (property::TARGET_REF, bytes_scalar_encoded_len(16)),
            ],
        );
    }

    pub(crate) fn record_legs(
        &mut self,
        entry_vid: VId,
        entry: &Entry,
        book: &BookContext,
    ) -> Result<(), KernelError> {
        let applied_zero = crate::rows::mantissa_scalar("applied", 0)?;
        for (i, leg) in entry.proposal.legs.iter().enumerate() {
            let ordinal =
                u16::try_from(i).map_err(|_| KernelError::Corrupt("more than u16 legs".into()))?;
            let lvid = crate::rows::leg_vid(entry_vid, ordinal);
            let mut mirrors =
                fa_model::leg_mirrors(leg, ordinal, entry.proposal.effective_date, &book.units)?;
            mirrors.push((property::APPLIED, applied_zero.clone()));
            self.create_vertex(relation::HAS_LEG, lvid, 1, &mirrors);
            self.add_edge(
                relation::HAS_LEG,
                &[(property::ORDINAL, CanonicalScalar::Int(i64::from(ordinal)))],
            );
            self.add_edge(relation::POSTS_TO, &[]);
            self.add_edge(relation::IN_UNIT, &[]);
            for (dimension, _) in &leg.dimension_set {
                self.add_edge(
                    relation::FOR,
                    &[(
                        property::DIMENSION_ID,
                        CanonicalScalar::Int(i64::from(*dimension)),
                    )],
                );
            }
        }
        Ok(())
    }

    pub(crate) fn record_limit_cell_move(
        &mut self,
        relation: fgdb_delta_types::RelationId,
        cell: VId,
        before: &crate::limit::LimitCell,
        after: &crate::limit::LimitCell,
    ) -> Result<(), KernelError> {
        self.set_vertex_property(
            relation,
            cell,
            property::GENERATION,
            Some(CanonicalScalar::Int(before.generation)),
            Some(CanonicalScalar::Int(after.generation)),
        );
        for (key, b, a) in [
            (
                property::DEBITS_POSTED,
                before.debits_posted,
                after.debits_posted,
            ),
            (
                property::CREDITS_POSTED,
                before.credits_posted,
                after.credits_posted,
            ),
            (
                property::DEBITS_PENDING,
                before.debits_pending,
                after.debits_pending,
            ),
            (
                property::CREDITS_PENDING,
                before.credits_pending,
                after.credits_pending,
            ),
        ] {
            self.set_vertex_property(
                relation,
                cell,
                key,
                Some(crate::rows::mantissa_scalar("limit.before", b)?),
                Some(crate::rows::mantissa_scalar("limit.after", a)?),
            );
        }
        Ok(())
    }

    pub(crate) fn record_object_stage(
        &mut self,
        relation: fgdb_delta_types::RelationId,
        bytes: &[u8],
    ) {
        if bytes.len() <= object::CHUNK_BYTES {
            return;
        }
        for part in bytes.chunks(object::CHUNK_BYTES) {
            self.add_row(relation, 156 + bytes_scalar_encoded_len(part.len()));
        }
    }

    pub(crate) fn add_edge(
        &mut self,
        relation: fgdb_delta_types::RelationId,
        props: &[(fgdb_delta_types::PropertyKeyId, CanonicalScalar)],
    ) {
        let bytes = 75
            + props
                .iter()
                .map(|(_, v)| 12 + v.canonical_encoded_len().expect("canonical scalar"))
                .sum::<usize>();
        self.add_row(relation, bytes);
    }

    pub(crate) fn set_vertex_property(
        &mut self,
        relation: fgdb_delta_types::RelationId,
        vid: VId,
        key: fgdb_delta_types::PropertyKeyId,
        before: Option<CanonicalScalar>,
        after: Option<CanonicalScalar>,
    ) {
        self.touch_relation(relation);
        if let Some(created) = self.created_vertices.get_mut(&vid) {
            if let Some(undo) = &mut self.undo {
                undo.created_vertices
                    .entry(vid)
                    .or_insert_with(|| Some(created.clone()));
            }
            let after_len = after
                .as_ref()
                .map(|value| value.canonical_encoded_len().expect("canonical scalar"));
            let before_len = match after_len {
                Some(len) => created.props.insert(key, len),
                None => created.props.remove(&key),
            };
            let removed = before_len.map_or(0, |len| 12 + len);
            let added = after_len.map_or(0, |len| 12 + len);
            created.row_bytes = created.row_bytes - removed + added;
            self.row_bytes = self.row_bytes - removed + added;
            return;
        }
        if let Some(undo) = &mut self.undo {
            undo.property_updates.entry((vid, key)).or_insert_with(|| {
                self.property_updates
                    .get(&(vid, key))
                    .map(|update| update.row_bytes)
            });
        }
        let update = self
            .property_updates
            .entry((vid, key))
            .or_insert_with(|| PropertyUpdate {
                before_len: opt_scalar_len(before.as_ref()),
                before,
                row_bytes: 0,
            });
        let previous_bytes = update.row_bytes;
        let row_bytes = if update.before == after {
            0
        } else {
            30 + update.before_len + opt_scalar_len(after.as_ref())
        };
        update.row_bytes = row_bytes;
        self.row_bytes = self.row_bytes - previous_bytes + row_bytes;
    }

    #[must_use]
    pub(crate) fn total_bytes(&self) -> usize {
        if self.relations.is_empty() {
            0
        } else {
            70 + 53 * self.relations.len() + self.row_bytes
        }
    }
}

pub(crate) fn batch_byte_budget_refusal(
    bytes: usize,
    member: Option<usize>,
    total_members: usize,
) -> Refusal {
    let max_bytes = fa_model::limits::MAX_BATCH_TEMPLATE_BYTES;
    let splits = bytes.div_ceil(max_bytes).max(2);
    let per_batch = total_members.div_ceil(splits).max(1);
    let message = match member {
        Some(i) => format!(
            "batch member {i} of {total_members} brings the batch's canonical LogicalDeltaTemplate to {bytes} bytes, exceeding max_batch_template_bytes ({max_bytes}); nothing in the batch was recorded"
        ),
        None => format!(
            "batch canonical LogicalDeltaTemplate is {bytes} bytes ({total_members} members), exceeding max_batch_template_bytes ({max_bytes}); nothing in the batch was recorded"
        ),
    };
    let mut refusal = Refusal::new(
        code::BATCH_BYTE_BUDGET,
        exit::REFUSAL,
        message,
        "registries/limits.toml max_batch_template_bytes (14439152); plan §5.8, §17",
        format!(
            "split the {total_members} entries into at least {splits} batches of at most {per_batch} entries each so each batch stays within {max_bytes} bytes"
        ),
    )
    .at("template_bytes", bytes)
    .at("max_batch_template_bytes", max_bytes)
    .at("recommended_splits", splits);
    if let Some(i) = member {
        refusal = refusal.at("member", i);
    }
    refusal
}

/// [`stage_outcome_tracked`] without a byte budget; only tests stage this way.
#[cfg(test)]
fn stage_outcome(
    cx: &QueryCx,
    stage: &mut WriteBatch,
    book: Id128,
    vid: VId,
    body: &OutcomeBody,
) -> Result<(), KernelError> {
    stage_outcome_tracked(
        cx,
        stage,
        &mut TemplateByteTracker::default(),
        book,
        vid,
        body,
    )
}

pub(crate) fn stage_outcome_tracked(
    cx: &QueryCx,
    stage: &mut WriteBatch,
    tracker: &mut TemplateByteTracker,
    book: Id128,
    vid: VId,
    body: &OutcomeBody,
) -> Result<(), KernelError> {
    let bytes = body.canonical_bytes()?;
    let mut props = vec![(
        property::FA_PAYLOAD,
        scalar_bytes(
            "intent outcome",
            object::payload(ObjectKind::IntentOutcome, &bytes)?,
        )?,
    )];
    if bytes.len() > object::CHUNK_BYTES {
        props.push((
            property::BOOK_ID,
            scalar_bytes("intent outcome book", book.0.to_vec())?,
        ));
    }
    object::stage(
        cx,
        stage,
        book,
        vid,
        label::INTENT_OUTCOME,
        ObjectKind::IntentOutcome,
        &bytes,
    )?;
    tracker.record_object_stage(relation::IN_BATCH, &bytes);
    tracker.create_vertex(relation::IN_BATCH, vid, 1, &props);
    stage.create_vertex(vid, vec![label::INTENT_OUTCOME], props);
    Ok(())
}

fn member_refusal(index: usize, refusal: Refusal) -> Refusal {
    Refusal {
        message: format!(
            "batch member {index}: {}; nothing in the batch was recorded",
            refusal.message
        ),
        ..refusal
    }
    .at("member", index)
}

fn outcome_conflict(outcome: VId) -> Refusal {
    Refusal::new(
        code::IDEMPOTENCY_CONFLICT,
        exit::CONFLICT,
        format!(
            "batch key reused with a different request; the recorded outcome is {:032x}",
            outcome.0
        ),
        "plan §5.9 (one IntentOutcome per key; FA-INV-09)",
        "resubmit the identical batch to get the recorded outcome, or use a new batch key for new content",
    )
}

/// The request identity an IntentOutcome records: the batch key and the
/// members' derived entry identities, in order. Member content is judged by
/// the kernel's own retry law (plan §4.9: exact bytes, else a private
/// plaintext comparison under the book key), so no plaintext-derived digest
/// is ever persisted, and fresh seal salts on a retry change nothing.
#[must_use]
pub fn request_digest(key: &[u8], members: &[VId]) -> [u8; 32] {
    let vids: Vec<u8> = members.iter().flat_map(|v| v.0.to_le_bytes()).collect();
    fa_model::domain_digest(b"fa:batch-request:v1", &[key, &vids])
}

fn member_request(intent: &fa_intents::PostIntent, capability: &Capability) -> PostRequest {
    PostRequest {
        proposal: intent.proposal().clone(),
        approvals: intent.approvals().to_vec(),
        capability: capability.clone(),
        plan_certificate: None,
    }
}

/// Judge `batch` against its recorded IntentOutcome (plan §5.9): the
/// identical retry when every member is the recorded outcome of its own
/// identity under the kernel's retry law and the outcome lists exactly
/// those entries in order; otherwise the conflict. A member whose content
/// differs from its recorded entry is that member's own conflict.
fn judge_retry<V: Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capabilities: &[Capability],
    batch: &PostBatch,
    admission: Admission,
    outcome: VId,
) -> Outcome<BatchPosted> {
    let closing = match singleton_closing_draft(batch, admission) {
        Ok(closing) => closing,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let case_closing = match singleton_case_closing(batch, admission) {
        Ok(proof) => proof,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let revaluation = match singleton_revaluation_draft(batch, admission) {
        Ok(proof) => proof,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let carrying = match independent_carrying_batch(batch, admission)? {
        Ok(carrying) => carrying,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let disposal = match independent_disposal_batch(batch, admission) {
        Ok(disposal) => disposal,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let asset_charge =
        match independent_asset_charge_batch(db, book, capabilities, batch, admission)? {
            Ok(proof) => proof,
            Err(refusal) => return Ok(Err(refusal)),
        };
    let proofs = AggregateProofs {
        carrying,
        disposal,
        asset_charge,
        closing,
        case_closing,
        revaluation,
    };
    // A single-entry claim at this common key is a conflict. Read only its
    // VID-only metadata here: a batch capability need not reach that entry.
    let lookup = db.begin(&ctx.txn())?;
    let label = lookup.vertex_has_label(db, outcome, label::INTENT_OUTCOME)?;
    let target = lookup.vertex_property(db, outcome, property::TARGET_REF)?;
    lookup.abort();
    if label != Some(true) || target.is_some() {
        return Ok(Err(outcome_conflict(outcome)));
    }
    let mut entries = Vec::with_capacity(batch.members().len());
    let mut publications = Vec::with_capacity(batch.members().len());
    // Reused only while each member's transaction has the same basis.
    let mut reconciliation = None;
    for (i, (intent, capability)) in batch.members().iter().zip(capabilities).enumerate() {
        match prepare_member(
            db,
            ctx,
            book,
            member_request(intent, capability),
            admission,
            MemberPreparation { txn: None, proofs },
            None,
            &mut reconciliation,
        )? {
            Err(refusal) => return Ok(Err(member_refusal(i, refusal))),
            Ok(PostPreparation::AlreadyRecorded(posted)) => {
                publications.push(posted.recorded_at());
                entries.push(posted.entry_ref());
            }
            Ok(PostPreparation::Ready(prepared)) => {
                prepared.abort();
                return Ok(Err(outcome_conflict(outcome)));
            }
        }
    }
    let vids: Vec<VId> = entries.iter().map(|e| e.vid).collect();
    // Admission above established reach of every requested Entry. Match the
    // complete stored membership from adjacency metadata before loading the
    // outcome's ordered refs/digests, including for scoped capabilities.
    let mut members = db.in_neighbours(outcome, relation::IN_BATCH)?;
    let mut expected_members = vids.clone();
    members.sort_unstable();
    expected_members.sort_unstable();
    if members != expected_members {
        return Ok(Err(outcome_conflict(outcome)));
    }
    let Some((body, recorded_at)) = read_outcome(db, &ctx.query(), outcome)? else {
        return Err(KernelError::Corrupt(
            "an intent outcome vanished between two reads".into(),
        ));
    };
    let Some(before) = recorded_at.0.checked_sub(1).map(CommitSeq) else {
        return Ok(Err(outcome_conflict(outcome)));
    };
    let Some(root) = db.vertex(outcome)? else {
        return Ok(Err(outcome_conflict(outcome)));
    };
    if !original_vertex(db, &root, recorded_at, before)?
        || publications.iter().any(|sequence| *sequence != recorded_at)
    {
        return Ok(Err(outcome_conflict(outcome)));
    }
    for vid in &vids {
        if !original_edge(db, relation::IN_BATCH, *vid, outcome, recorded_at)? {
            return Ok(Err(outcome_conflict(outcome)));
        }
    }
    if entries != body.entries
        || body.request_digest != request_digest(batch.idempotency_key(), &vids)
    {
        return Ok(Err(outcome_conflict(outcome)));
    }
    Ok(Ok(BatchPosted {
        outcome,
        entries,
        periods: Vec::new(),
        recorded_at,
        already_recorded: true,
    }))
}

/// The classes a batch member may post in this slice: an allocation has its
/// own planner and a migration chunk belongs to its run.
pub(crate) fn batchable(class: fa_model::EntryClass) -> bool {
    use fa_model::EntryClass as C;
    [
        C::ORIGINAL,
        C::ADJUSTING,
        C::REVERSAL,
        C::PENDING,
        C::RESOLUTION,
    ]
    .contains(&class)
}

/// Authorize every member's request under `admission` before any
/// observation (doctrine 8).
pub(crate) fn authorize_members<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    capability: &Capability,
    batch: &PostBatch,
    admission: Admission,
) -> Outcome<()> {
    for (index, intent) in batch.members().iter().enumerate() {
        if let Err(refusal) = crate::post::authorize_request(
            db,
            book,
            &member_request(intent, capability),
            admission,
        )? {
            return Ok(Err(member_refusal(index, refusal)));
        }
        // The complete source is observed during history hydration and exact
        // plan retry too, before per-member posting preparation is reached.
        if crate::disposal::has_basis(intent.proposal())
            && !admission.admits_confined_draft_sources(capability)
            && let Err(refusal) = crate::disposal::authorize(db, book, capability)?
        {
            return Ok(Err(member_refusal(index, refusal)));
        }
        if crate::asset_cost::has_basis(intent.proposal())
            && let Err(refusal) = crate::asset_cost::authorize(db, book, capability)?
        {
            return Ok(Err(member_refusal(index, refusal)));
        }
        if (intent.proposal().class == EntryClass::REVALUATION
            || crate::revaluation::is_source_bound(intent.proposal()))
            && let Err(refusal) = crate::revaluation::authorize(db, book, capability)?
        {
            return Ok(Err(member_refusal(index, refusal)));
        }
    }
    Ok(Ok(()))
}

/// Commit `batch` atomically under `capability` (plan §5.8): every member
/// through the production pipeline in one transaction, then the batch's
/// IntentOutcome, in one commit.
pub async fn post_batch<V: Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capability: Capability,
    batch: PostBatch,
) -> Outcome<BatchPosted> {
    post_batch_in(db, ctx, book, capability, batch, None, None).await
}

/// [`post_batch`] for the long-lived owner of `db`, which keeps `carried`
/// between its writes so the batch checks only the commits since the last
/// (fa-rcw1). `carried` must only ever travel with this `db`.
pub async fn post_batch_carrying<V: Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capability: Capability,
    batch: PostBatch,
    carried: &mut crate::post::CarriedHistory,
) -> Outcome<BatchPosted> {
    post_batch_in(db, ctx, book, capability, batch, None, Some(carried)).await
}

/// [`post_batch`] through the substrate's production crash-point seam
/// (`WriteTxn::commit_with_crash`), for the lab campaign that crashes a
/// batch's one publication at each registered point and checks the book
/// after reopening (fa-0fl). `None` is `post_batch`: both run this one path.
#[doc(hidden)]
pub async fn post_batch_with_crash<V: Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capability: Capability,
    batch: PostBatch,
    crash_at: Option<fgdb::CrashPoint>,
) -> Outcome<BatchPosted> {
    post_batch_in(db, ctx, book, capability, batch, crash_at, None).await
}

async fn post_batch_in<V: Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capability: Capability,
    batch: PostBatch,
    crash_at: Option<fgdb::CrashPoint>,
    carried: Option<&mut crate::post::CarriedHistory>,
) -> Outcome<BatchPosted> {
    if let Err(refusal) = authorize_members(db, book, &capability, &batch, Admission::Commit)? {
        return Ok(Err(refusal));
    }
    ctx.query()
        .checkpoint()
        .map_err(WriteTxnError::Interrupted)?;
    if let Err(refusal) = crate::scratch::ensure_history(db, ctx).await? {
        return Ok(Err(refusal));
    }
    let capabilities = vec![capability; batch.members().len()];
    let staged = match stage_batch_with(
        db,
        ctx,
        book,
        &capabilities,
        &batch,
        Admission::Commit,
        carried,
    )? {
        Err(refusal) => return Ok(Err(refusal)),
        Ok(BatchStage::Recorded(posted)) => return Ok(Ok(posted)),
        Ok(BatchStage::Staged(staged)) => staged,
    };
    commit_batch_with_crash(
        db,
        ctx,
        book,
        &capabilities,
        &batch,
        Admission::Commit,
        staged,
        crash_at,
    )
    .await
}

/// A batch staged in one open transaction: its members and its
/// IntentOutcome, not yet published. A draft's promotion stages its own
/// record into the same transaction before committing it.
pub(crate) struct StagedBatch {
    pub(crate) txn: WriteTxn,
    pub(crate) outcome: VId,
    pub(crate) entries: Vec<EntryRef>,
    pub(crate) periods: Vec<String>,
    pub(crate) template_tracker: TemplateByteTracker,
    prepared: Vec<Entry>,
    security_policy_epoch: u64,
    /// A rehearsal can be retained and inspected, but never published.
    planning: bool,
    /// Source-bound members depend on this transaction's complete committed
    /// basis, including the role history a prior-period adjustment reads.
    aggregate: bool,
}

impl StagedBatch {
    pub(crate) fn prepared_entries(&self) -> &[Entry] {
        &self.prepared
    }
}

pub(crate) enum BatchStage {
    Staged(Box<StagedBatch>),
    /// The identical batch's recorded outcome (FA-INV-09): nothing staged.
    Recorded(BatchPosted),
}

/// Stage `batch` (plan §5.8): every member through the posting pipeline in
/// one carried transaction, member `i` under `capabilities[i]` and
/// `admission`, then the batch's IntentOutcome with an `IN_BATCH` edge from
/// each member. Any refusal stages nothing.
pub(crate) fn stage_batch<V: Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capabilities: &[Capability],
    batch: &PostBatch,
    admission: Admission,
) -> Outcome<BatchStage> {
    stage_batch_with(db, ctx, book, capabilities, batch, admission, None)
}

/// [`stage_batch`] with the owner's carried history: every member shares its
/// reconciliation history, and the batch's capacity admission answers from
/// its summary where that proves the effects fit (fa-rcw1).
fn stage_batch_with<V: Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capabilities: &[Capability],
    batch: &PostBatch,
    admission: Admission,
    carried: Option<&mut crate::post::CarriedHistory>,
) -> Outcome<BatchStage> {
    let mut fresh = None;
    let (reconciliation, capacity) = match carried {
        Some(carried) => (&mut carried.reconciliation, Some(&mut carried.capacity)),
        None => (&mut fresh, None),
    };
    ctx.txn().checkpoint().map_err(WriteTxnError::Interrupted)?;
    if capabilities.len() != batch.members().len() {
        return Err(KernelError::Corrupt(
            "a batch is staged with one capability per member".into(),
        ));
    }
    let closing = match singleton_closing_draft(batch, admission) {
        Ok(closing) => closing,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let case_closing = match singleton_case_closing(batch, admission) {
        Ok(proof) => proof,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let revaluation = match singleton_revaluation_draft(batch, admission) {
        Ok(proof) => proof,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if let Some((i, member)) = batch.members().iter().enumerate().find(|(_, m)| {
        // A restatement case's own Post batches its case-bound entries
        // (plan §8.3); the posting law checks each is the case's.
        !batchable(m.proposal().class)
            && !(m.proposal().class == EntryClass::CLOSING
                && (closing.is_some() || case_closing.is_some()))
            && !(m.proposal().class == EntryClass::REVALUATION && revaluation.is_some())
            && !(matches!(admission, Admission::Case(_))
                && crate::case::case_bound(m.proposal().class))
    }) {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!(
                "batch member {i}: a {} entry cannot join a batch; nothing in the batch was recorded",
                member.proposal().class.name().unwrap_or("?")
            ),
            "plan §5.8 (batches of PostEntry intents; allocations and migration chunks have their own runs)",
            "post the allocation or migration chunk through its own verb, and batch only Original, Adjusting, Reversal, Pending and Resolution entries",
        )));
    }
    if batch
        .members()
        .iter()
        .any(|member| member.proposal().idempotency_key == batch.idempotency_key())
    {
        return Ok(Err(crate::outcome::key_conflict()));
    }
    let ovid = outcome_vid(book, batch);
    let carrying = match independent_carrying_batch(batch, admission)? {
        Ok(carrying) => carrying,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let disposal = match independent_disposal_batch(batch, admission) {
        Ok(disposal) => disposal,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let asset_charge =
        match independent_asset_charge_batch(db, book, capabilities, batch, admission)? {
            Ok(proof) => proof,
            Err(refusal) => return Ok(Err(refusal)),
        };
    let proofs = AggregateProofs {
        carrying,
        disposal,
        asset_charge,
        closing,
        case_closing,
        revaluation,
    };
    let mut txn: Option<WriteTxn> = None;
    let mut tracker = TemplateByteTracker::default();
    // Every member stages into one transaction, so the reconciliation
    // history is verified (or carried forward) once at its basis and shared
    // by every member (fa-rcw1).
    let mut members: Vec<BatchMember> = Vec::with_capacity(batch.members().len());
    let mut resolved = Vec::with_capacity(batch.members().len());
    let mut security_policy_epoch = None;
    let planning = matches!(admission, Admission::Plan | Admission::PlanDraft(_));
    for (i, (intent, capability)) in batch.members().iter().zip(capabilities).enumerate() {
        let request = member_request(intent, capability);
        let prepared = match prepare_member(
            db,
            ctx,
            book,
            request,
            admission,
            MemberPreparation {
                txn: txn.take(),
                proofs,
            },
            Some(std::mem::take(&mut tracker)),
            reconciliation,
        )? {
            Err(refusal) => return Ok(Err(member_refusal(i, refusal))),
            // The member's identity is taken. Admission already ran for it,
            // so the outcome may be observed: with a recorded outcome this is
            // the identical retry or a conflict; without one, the member was
            // posted outside any batch.
            Ok(PostPreparation::AlreadyRecorded(posted)) => {
                let lookup = db.begin(&ctx.txn())?;
                let present = lookup
                    .vertex_has_label(db, ovid, label::INTENT_OUTCOME)?
                    .is_some();
                lookup.abort();
                if present {
                    return if i == 0 {
                        Ok(
                            judge_retry(db, ctx, book, capabilities, batch, admission, ovid)?
                                .map(BatchStage::Recorded),
                        )
                    } else {
                        Ok(Err(outcome_conflict(ovid)))
                    };
                }
                return Ok(Err(Refusal::new(
                    code::IDEMPOTENCY_CONFLICT,
                    exit::CONFLICT,
                    format!(
                        "batch member {i} is already recorded as entry {:032x}, outside this batch; nothing in the batch was recorded",
                        posted.entry_ref().vid.0
                    ),
                    "plan §5.8 (a batch commits only new entries)",
                    "give the member a new idempotency key, or leave the recorded entry out of the batch",
                )));
            }
            Ok(PostPreparation::Ready(prepared)) => prepared,
        };
        let epoch = prepared.security_policy_epoch();
        if security_policy_epoch.is_some_and(|prior| prior != epoch) {
            prepared.abort();
            return Err(KernelError::Corrupt(
                "batch members observed different security policy epochs".into(),
            ));
        }
        security_policy_epoch = Some(epoch);
        resolved.push(prepared.entry().clone());
        let (staged, member, next_tracker) = prepared.into_member(planning, proofs, admission)?;
        tracker = next_tracker;
        let current_bytes = tracker.total_bytes();
        if current_bytes > fa_model::limits::MAX_BATCH_TEMPLATE_BYTES {
            staged.abort();
            return Ok(Err(batch_byte_budget_refusal(
                current_bytes,
                Some(i),
                batch.members().len(),
            )));
        }
        // After the first member's admission, the outcome identity is a
        // witness: absent here, and a concurrent identical batch conflicts.
        // A recorded outcome whose first member is new is another request.
        if i == 0 {
            let legacy_key_vid = fa_model::entry_vid(
                book.book_id,
                &batch.principal().0.to_le_bytes(),
                batch.idempotency_key(),
            );
            if staged
                .vertex_has_label(db, ovid, label::INTENT_OUTCOME)?
                .is_some()
                || staged
                    .vertex_has_label(db, legacy_key_vid, label::ENTRY)?
                    .is_some()
            {
                staged.abort();
                return Ok(Err(outcome_conflict(ovid)));
            }
            if let Err(refusal) =
                crate::outcome::require_unused_legacy_key(&staged, db, book, ovid)?
            {
                staged.abort();
                return Ok(Err(refusal));
            }
        }
        members.push(member);
        txn = Some(staged);
    }
    let Some(mut txn) = txn else {
        return Err(KernelError::Corrupt(
            "a validated batch has no member".into(),
        ));
    };
    if carrying.is_some()
        && let Err(refusal) = admit_carrying_batch_accounts(db, ctx, book, &resolved, txn.basis())?
    {
        txn.abort();
        return Ok(Err(refusal));
    }
    let vids: Vec<VId> = members.iter().map(|m| m.entry_ref.vid).collect();
    let body = OutcomeBody {
        request_digest: request_digest(batch.idempotency_key(), &vids),
        entries: members.iter().map(|m| m.entry_ref).collect(),
    };
    let mut stage = WriteBatch::new(relation::IN_BATCH);
    stage_outcome_tracked(
        &ctx.query(),
        &mut stage,
        &mut tracker,
        book.book_id,
        ovid,
        &body,
    )?;
    for m in &members {
        let evid = m.entry_ref.vid;
        tracker.add_edge(relation::IN_BATCH, &[]);
        stage.add_edge(edge_id(relation::IN_BATCH, evid, ovid), evid, ovid, vec![]);
    }
    let total_bytes = tracker.total_bytes();
    if total_bytes > fa_model::limits::MAX_BATCH_TEMPLATE_BYTES {
        txn.abort();
        return Ok(Err(batch_byte_budget_refusal(
            total_bytes,
            Some(batch.members().len().saturating_sub(1)),
            batch.members().len(),
        )));
    }
    txn.write_ordered(db, vec![stage])?;
    let accounts = crate::register_capacity::accounts(resolved.iter().map(|e| &e.proposal));
    let staged = members.iter().map(|m| m.entry_ref.vid);
    let admitted = match capacity {
        Some(history) => crate::register_capacity::admit_carried(
            &txn,
            db,
            ctx,
            book.book_id,
            &accounts,
            staged,
            history,
        )?,
        None => crate::register_capacity::admit(&txn, db, ctx, book.book_id, &accounts, staged)?,
    };
    if let Err(refusal) = admitted {
        txn.abort();
        return Ok(Err(refusal));
    }
    let aggregate = resolved.iter().try_fold(
        carrying.is_some() || disposal.is_some(),
        |aggregate, entry| {
            crate::post::requires_aggregate_basis(&entry.proposal)
                .map(|required| aggregate || required)
        },
    )?;
    Ok(Ok(BatchStage::Staged(Box::new(StagedBatch {
        txn,
        outcome: ovid,
        entries: body.entries,
        periods: members.into_iter().map(|m| m.period).collect(),
        template_tracker: tracker,
        prepared: resolved,
        security_policy_epoch: security_policy_epoch.ok_or_else(|| {
            KernelError::Corrupt("a validated batch has no security policy epoch".into())
        })?,
        planning,
        aggregate,
    }))))
}

/// Publish a staged batch once. Every member's capability is judged current
/// again at the frontier (expiry); a lost race on a member identity is
/// judged against the recorded outcome under the same admission.
pub(crate) async fn commit_batch<V: Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capabilities: &[Capability],
    batch: &PostBatch,
    admission: Admission,
    staged: Box<StagedBatch>,
) -> Outcome<BatchPosted> {
    commit_batch_with_crash(db, ctx, book, capabilities, batch, admission, staged, None).await
}

/// [`commit_batch`] through the substrate's production crash-point seam
/// (fa-0fl); `None` is `commit_batch`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn commit_batch_with_crash<V: Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capabilities: &[Capability],
    batch: &PostBatch,
    admission: Admission,
    staged: Box<StagedBatch>,
    crash_at: Option<fgdb::CrashPoint>,
) -> Outcome<BatchPosted> {
    if staged.planning || matches!(admission, Admission::Plan | Admission::PlanDraft(_)) {
        staged.txn.abort();
        return Err(KernelError::Corrupt(
            "a batch rehearsal cannot be published; commit its authenticated plan".into(),
        ));
    }
    let StagedBatch {
        mut txn,
        outcome: ovid,
        entries,
        periods,
        prepared,
        template_tracker,
        aggregate,
        ..
    } = *staged;
    let total_bytes = template_tracker.total_bytes();
    if total_bytes > fa_model::limits::MAX_BATCH_TEMPLATE_BYTES {
        txn.abort();
        return Ok(Err(batch_byte_budget_refusal(
            total_bytes,
            Some(batch.members().len().saturating_sub(1)),
            batch.members().len(),
        )));
    }
    let commit = ctx.commit();
    commit.checkpoint().map_err(WriteTxnError::Interrupted)?;
    for capability in capabilities {
        if let Err(d) = fa_policy::current(capability, db.frontier()?) {
            txn.abort();
            return Ok(Err(policy::refusal(&d)));
        }
    }
    if aggregate
        && let Err(refusal) = crate::post::check_aggregate_basis(txn.basis(), db.frontier()?)
    {
        txn.abort();
        return Ok(Err(refusal));
    }
    if txn.basis() != db.frontier()? {
        // Period-wide hold capacity, like gross register representability,
        // can change without touching this batch's point-read accounts. A
        // delayed publication must judge the whole atomic result at the
        // current prefix while retaining every original admission witness.
        let capacity_entries: Vec<_> = entries
            .iter()
            .zip(&prepared)
            .map(|(reference, entry)| (reference.vid, entry))
            .collect();
        if let Err(refusal) =
            crate::register_capacity::admit_publication(db, ctx, book.book_id, &capacity_entries)?
        {
            let refusal = if refusal.code == code::REGISTER_CAPACITY {
                Refusal::new(
                    code::CONFLICT,
                    exit::CONFLICT,
                    format!(
                        "a publication after prepared prefix {} exhausted register capacity: {}",
                        txn.basis().0,
                        refusal.message,
                    ),
                    "plan §5.3–§5.4 (register and pending-hold capacity at publication)",
                    "re-plan the whole batch against the current journal; reduce gross activity or resolve existing holds in the affected period if the fresh plan exceeds capacity",
                )
            } else {
                refusal
            };
            txn.abort();
            return Ok(Err(refusal));
        }
    }
    match txn.commit_with_crash(db, &commit, crash_at).await {
        Ok(seq) => Ok(Ok(BatchPosted {
            outcome: ovid,
            entries,
            periods,
            recorded_at: seq,
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(Refusal::new(
                code::CONFLICT,
                exit::CONFLICT,
                format!(
                    "a concurrent commit invalidated a witness this batch read: {detail}; nothing in the batch was recorded"
                ),
                "FG-LAW-FCW-01 (first committer wins)",
                "re-plan and retry the batch; if a close or a policy activation won, the period-law or stale-approval refusal will say so",
            )))
        }
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => {
            let lookup = db.begin(&ctx.txn())?;
            let present = lookup
                .vertex_has_label(db, ovid, label::INTENT_OUTCOME)?
                .is_some();
            lookup.abort();
            if present {
                judge_retry(db, ctx, book, capabilities, batch, admission, ovid)
            } else {
                Ok(Err(Refusal::new(
                    code::IDEMPOTENCY_CONFLICT,
                    exit::CONFLICT,
                    "a member's identity was taken by a concurrent commit; nothing in the batch was recorded",
                    "plan §4.9 (identities are derived, first committer wins)",
                    "retry the identical batch: a member recorded outside it is then named",
                )))
            }
        }
        Err(e) => Err(e.into()),
    }
}

fn plan_invalidated(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::PLAN_INVALIDATED,
        exit::CONFLICT,
        message,
        "plan §5.8 / §10.4 (authenticated ordered batch and exact native effects)",
        "dry-run the complete batch again with current authority and approvals, then commit its unchanged plan before any other publication",
    )
}

fn plan_codec(error: fa_intents::IntentError) -> KernelError {
    KernelError::Corrupt(format!("kernel-produced batch plan: {error}"))
}

fn plan_authentication(
    book: &BookContext,
    certificate: &BatchPlanCertificate,
) -> Result<[u8; 32], KernelError> {
    let key = fgdb_crypto::derive_key("fa:batch-plan-authentication-key:v1", &book.seal_key.0);
    Ok(fgdb_crypto::keyed_hash(
        &key,
        &certificate.authentication_bytes().map_err(plan_codec)?,
    )
    .0)
}

fn authorize_plan_batch<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    capability: &Capability,
    batch: &PostBatch,
    admission: Admission,
) -> Outcome<()> {
    if let Err(denial) = fa_policy::reach(capability, &fa_policy::Reach::whole_book(true), None) {
        return Ok(Err(policy::refusal(&denial)));
    }
    authorize_members(db, book, capability, batch, admission)
}

fn plan_retention(
    ctx: &PurposeContexts,
    book: &BookContext,
    plan: &BatchPlan,
    entries: &[EntryRef],
    tracker: &mut TemplateByteTracker,
) -> Result<WriteBatch, KernelError> {
    let digest = plan.certificate_digest().map_err(plan_codec)?;
    let cvid = crate::plan::plan_certificate_vid(book.book_id, &digest);
    let bytes = plan.canonical_bytes().map_err(plan_codec)?;
    let mut retention = WriteBatch::new(relation::CITES);
    object::stage(
        &ctx.query(),
        &mut retention,
        book.book_id,
        cvid,
        label::CERTIFICATE,
        ObjectKind::BatchPlan,
        &bytes,
    )?;
    tracker.record_object_stage(relation::CITES, &bytes);
    let props = vec![
        (
            property::FA_PAYLOAD,
            scalar_bytes(
                "batch plan",
                object::payload(ObjectKind::BatchPlan, &bytes)?,
            )?,
        ),
        (
            property::FA_DIGEST,
            scalar_bytes("batch plan certificate digest", digest.to_vec())?,
        ),
        (
            property::BOOK_ID,
            scalar_bytes("batch plan book", book.book_id.0.to_vec())?,
        ),
    ];
    tracker.create_vertex(relation::CITES, cvid, 1, &props);
    retention.create_vertex(cvid, vec![label::CERTIFICATE], props);
    for vid in entries
        .iter()
        .map(|entry| entry.vid)
        .chain([outcome_vid(book, plan.batch())])
    {
        tracker.add_edge(relation::CITES, &[]);
        retention.add_edge(edge_id(relation::CITES, vid, cvid), vid, cvid, vec![]);
    }
    Ok(retention)
}

/// Rehearse the entire ordered batch in one transaction and abort it. Each
/// member sees earlier members' staged effects, exactly as at publication.
/// The complete native delta (including the IntentOutcome) is authenticated;
/// even certificate retention is staged before a successful plan is returned
/// so native capacity refusal cannot be hidden behind a successful preview.
pub fn plan_batch<V: Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capability: Capability,
    batch: PostBatch,
) -> Outcome<BatchPlan> {
    if let Err(refusal) = authorize_plan_batch(db, book, &capability, &batch, Admission::Plan)? {
        return Ok(Err(refusal));
    }
    let capabilities = vec![capability.clone(); batch.members().len()];
    let mut staged = match stage_batch(db, ctx, book, &capabilities, &batch, Admission::Plan)? {
        Err(refusal) => return Ok(Err(refusal)),
        Ok(BatchStage::Recorded(_)) => {
            return Ok(Err(plan_invalidated(
                "this batch already has a recorded outcome; no new effects were planned",
            )));
        }
        Ok(BatchStage::Staged(staged)) => staged,
    };
    let mut certificate = BatchPlanCertificate {
        book_id: batch.book_id(),
        branch_id: batch.branch_id(),
        principal: batch.principal(),
        capability_commitment: capability
            .commitment()
            .map_err(|error| KernelError::Corrupt(format!("batch capability: {error}")))?,
        intent_digest: batch.digest().map_err(plan_codec)?,
        prepared_digest: BatchPlan::prepared_digest(&staged.prepared, &staged.periods)
            .map_err(plan_codec)?,
        effects_digest: staged.txn.staged_effect_digest()?.0,
        snapshot_seq: staged.txn.basis(),
        security_policy_epoch: staged.security_policy_epoch,
        expires_at: capability.expires_at(),
        authentication: [0; 32],
    };
    certificate.authentication = plan_authentication(book, &certificate)?;
    let member_count = batch.members().len();
    let plan = BatchPlan::new(
        batch,
        staged.prepared.clone(),
        staged.periods.clone(),
        certificate,
    )
    .map_err(plan_codec)?;
    let retention = plan_retention(
        ctx,
        book,
        &plan,
        &staged.entries,
        &mut staged.template_tracker,
    )?;
    let total_bytes = staged.template_tracker.total_bytes();
    if total_bytes > fa_model::limits::MAX_BATCH_TEMPLATE_BYTES {
        staged.txn.abort();
        return Ok(Err(batch_byte_budget_refusal(
            total_bytes,
            Some(member_count.saturating_sub(1)),
            member_count,
        )));
    }
    staged.txn.write_ordered(db, vec![retention])?;
    staged.txn.abort();
    Ok(Ok(plan))
}

/// Hydrate checkpoint-opened history only after current whole-book and every
/// member's native planning authority have been admitted. Loading history
/// does not publish or alter the batch's intended trunk coordinate.
pub async fn plan_batch_with_history<V: Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capability: Capability,
    batch: PostBatch,
) -> Outcome<BatchPlan> {
    if let Err(refusal) = authorize_plan_batch(db, book, &capability, &batch, Admission::Plan)? {
        return Ok(Err(refusal));
    }
    ctx.query()
        .checkpoint()
        .map_err(WriteTxnError::Interrupted)?;
    if let Err(refusal) = crate::scratch::ensure_history(db, ctx).await? {
        return Ok(Err(refusal));
    }
    plan_batch(db, ctx, book, capability, batch)
}

fn original_vertex<V: Vfs + Clone>(
    db: &Database<V>,
    row: &VertexRow,
    born: CommitSeq,
    before: CommitSeq,
) -> Result<bool, KernelError> {
    Ok(row.created_at == born
        && row.retired_at.is_none()
        && db.vertex_at(row.vid, before)?.is_none()
        && db.vertex_at(row.vid, born)?.as_ref() == Some(row))
}

fn original_edge<V: Vfs + Clone>(
    db: &Database<V>,
    relation: fgdb_delta_types::RelationId,
    src: VId,
    dst: VId,
    born: CommitSeq,
) -> Result<bool, KernelError> {
    let eid = edge_id(relation, src, dst);
    let Some(edge) = db.edge(eid)? else {
        return Ok(false);
    };
    Ok(edge.entry.src == src
        && edge.entry.dst == dst
        && edge.entry.relation == relation
        && edge.entry.created_at == born
        && edge.entry.retired_at.is_none()
        && edge.props.is_empty()
        && db.edge_at(eid, born)?.as_ref() == Some(&edge))
}

/// Derive identity from the authenticated member, never from an outcome
/// row that merely claims to contain that member's digest.
fn planned_entry_ref(entry: &Entry) -> Result<EntryRef, Refusal> {
    let proposal = &entry.proposal;
    let vid = match proposal.class {
        EntryClass::REVERSAL => proposal
            .supersession
            .first()
            .map(|link| crate::rows::reversal_vid(link.target.vid)),
        EntryClass::RESOLUTION => proposal
            .pending
            .as_ref()
            .and_then(|pending| pending.resolution_of)
            .map(|target| crate::rows::resolution_vid(target.vid)),
        _ => Some(fa_model::entry_vid(
            proposal.book_id,
            &proposal.principal_ref.0.to_le_bytes(),
            &proposal.idempotency_key,
        )),
    }
    .ok_or_else(|| plan_invalidated("a planned member has no identity target"))?;
    Ok(entry.entry_ref(vid))
}

/// Exact lost-response recognition. An ordinary batch or a later copy of a
/// certificate cannot impersonate this plan's original atomic publication.
fn recorded_batch_plan<V: Vfs + Clone>(
    db: &Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    plan: &BatchPlan,
) -> Outcome<Option<BatchPosted>> {
    let ovid = outcome_vid(book, plan.batch());
    let Some(outcome) = db.vertex(ovid)? else {
        return Ok(Ok(None));
    };
    if prop(&outcome, property::TARGET_REF).is_some() {
        return Ok(Err(plan_invalidated(
            "the batch key belongs to another posting intent",
        )));
    }
    let certificate_digest = plan.certificate_digest().map_err(plan_codec)?;
    let cvid = crate::plan::plan_certificate_vid(book.book_id, &certificate_digest);
    let before = plan.certificate().snapshot_seq;
    let Some(born) = before.0.checked_add(1).map(CommitSeq) else {
        return Ok(Err(plan_invalidated("the planned basis has no successor")));
    };
    let entries = match plan
        .prepared_entries()
        .iter()
        .map(planned_entry_ref)
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(entries) => entries,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let member_vids: Vec<_> = entries.iter().map(|entry| entry.vid).collect();
    let (body, _) = outcome_of(db, &ctx.query(), &outcome, db.frontier()?)?;
    if !original_vertex(db, &outcome, born, before)?
        || matches!(prop(&outcome, property::BOOK_ID), Some(CanonicalScalar::Bytes(v)) if v.as_slice() != book.book_id.0)
        || body.entries != entries
        || body.request_digest != request_digest(plan.batch().idempotency_key(), &member_vids)
    {
        return Ok(Err(plan_invalidated(
            "the batch outcome is not this plan's original publication",
        )));
    }
    for (reference, prepared) in body.entries.iter().zip(plan.prepared_entries()) {
        let Some(entry) = db.vertex(reference.vid)? else {
            return Ok(Err(plan_invalidated("a planned batch member is missing")));
        };
        if *reference != prepared.entry_ref(reference.vid)
            || entry.labels.as_slice() != [label::ENTRY]
            || !crate::entry_storage::mirrors_match(&entry, prepared)?
            || crate::entry_storage::decode_at(db, &entry, db.frontier()?)? != *prepared
            || !original_vertex(db, &entry, born, before)?
            || !crate::outcome::verify_recorded(db, &ctx.query(), book, &entry, prepared)?
            || !original_edge(db, relation::IN_BATCH, reference.vid, ovid, born)?
            || !original_edge(db, relation::CITES, reference.vid, cvid, born)?
        {
            return Ok(Err(plan_invalidated(
                "a batch member or its original retaining links changed",
            )));
        }
    }
    let Some(certificate) = db.vertex(cvid)? else {
        return Ok(Err(plan_invalidated(
            "the recorded batch has no retained evidence for this exact plan",
        )));
    };
    if certificate.labels.as_slice() != [label::CERTIFICATE]
        || !original_vertex(db, &certificate, born, before)?
        || certificate.props.len() != 3
        || !matches!(prop(&certificate, property::BOOK_ID), Some(CanonicalScalar::Bytes(v)) if v.as_slice() == book.book_id.0)
        || !matches!(prop(&certificate, property::FA_DIGEST), Some(CanonicalScalar::Bytes(v)) if v.as_slice() == certificate_digest)
        || object::read(
            db,
            &ctx.query(),
            book.book_id,
            &certificate,
            label::CERTIFICATE,
            ObjectKind::BatchPlan,
            db.frontier()?,
            fa_intents::MAX_BATCH_PLAN_BYTES,
        )? != plan.canonical_bytes().map_err(plan_codec)?
        || !original_edge(db, relation::CITES, ovid, cvid, born)?
    {
        return Ok(Err(plan_invalidated(
            "the batch plan certificate or original outcome link changed",
        )));
    }
    Ok(Ok(Some(BatchPosted {
        outcome: ovid,
        entries: body.entries,
        periods: plan.periods().to_vec(),
        recorded_at: born,
        already_recorded: true,
    })))
}

/// Authenticate a batch rehearsal, re-admit current caller authority, and
/// reproduce its exact native transaction at the unchanged basis. The same
/// commit retains the complete plan, ordered outcome and every CITES edge.
/// An Agent's rehearsal never confers trunk publication authority.
pub async fn commit_batch_plan<V: Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capability: Capability,
    plan: BatchPlan,
) -> Outcome<BatchPosted> {
    if let Err(error) = plan.validate() {
        return Ok(Err(plan_invalidated(error.to_string())));
    }
    if plan.batch().book_id() != book.book_id || plan.batch().branch_id() != Id128::TRUNK {
        return Ok(Err(plan_invalidated(
            "the batch plan does not target this book's trunk",
        )));
    }
    let certificate = plan.certificate();
    let commitment = capability
        .commitment()
        .map_err(|error| KernelError::Corrupt(format!("batch capability: {error}")))?;
    let expected_authentication = plan_authentication(book, certificate)?;
    let difference = expected_authentication
        .iter()
        .zip(&certificate.authentication)
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b));
    if certificate.capability_commitment != commitment
        || certificate.expires_at != capability.expires_at()
        || difference != 0
    {
        return Ok(Err(plan_invalidated(
            "the batch plan authentication or acting capability changed",
        )));
    }
    // Authentication uses only the supplied bytes and this book's key.
    // Admit the unchanged capability before any policy/history/outcome
    // observation. The private token certifies the completed dry run, not
    // permission to publish: Agent trunk denial and current authority still
    // run in the production admission path for every member, also on retry.
    let admission = Admission::VerifiedBatch(VerifiedBatchPlan(()));
    if let Err(refusal) = authorize_plan_batch(db, book, &capability, plan.batch(), admission)? {
        return Ok(Err(refusal));
    }
    ctx.query()
        .checkpoint()
        .map_err(WriteTxnError::Interrupted)?;
    if let Err(refusal) = crate::scratch::ensure_history(db, ctx).await? {
        return Ok(Err(refusal));
    }
    match recorded_batch_plan(db, ctx, book, &plan)? {
        Err(refusal) => return Ok(Err(refusal)),
        Ok(Some(posted)) => return Ok(Ok(posted)),
        Ok(None) => {}
    }
    if db.frontier()? != certificate.snapshot_seq {
        return Ok(Err(plan_invalidated(
            "a publication changed the batch plan's exact basis",
        )));
    }
    let capabilities = vec![capability; plan.batch().members().len()];
    let mut staged = match stage_batch(db, ctx, book, &capabilities, plan.batch(), admission)? {
        Err(refusal) => {
            return Ok(Err(plan_invalidated(format!(
                "current batch admission refused: {} ({})",
                refusal.message, refusal.code,
            ))));
        }
        Ok(BatchStage::Recorded(_)) => {
            return Ok(Err(plan_invalidated(
                "the batch was recorded without this exact plan's retained evidence",
            )));
        }
        Ok(BatchStage::Staged(staged)) => staged,
    };
    if staged.txn.basis() != certificate.snapshot_seq
        || staged.security_policy_epoch != certificate.security_policy_epoch
        || staged.prepared != plan.prepared_entries()
        || staged.periods != plan.periods()
        || staged.txn.staged_effect_digest()?.0 != certificate.effects_digest
    {
        staged.txn.abort();
        return Ok(Err(plan_invalidated(
            "current native effects, resolved members, periods or policy differ from the batch plan",
        )));
    }
    let cvid = crate::plan::plan_certificate_vid(
        book.book_id,
        &plan.certificate_digest().map_err(plan_codec)?,
    );
    if db.vertex(cvid)?.is_some() {
        staged.txn.abort();
        return Ok(Err(plan_invalidated(
            "the batch certificate identity is already occupied",
        )));
    }
    let retention = plan_retention(
        ctx,
        book,
        &plan,
        &staged.entries,
        &mut staged.template_tracker,
    )?;
    staged.txn.write_ordered(db, vec![retention])?;
    match commit_batch(
        db,
        ctx,
        book,
        &capabilities,
        plan.batch(),
        admission,
        staged,
    )
    .await?
    {
        Ok(posted) if !posted.already_recorded => Ok(Ok(posted)),
        Ok(_) => match recorded_batch_plan(db, ctx, book, &plan)? {
            Ok(Some(posted)) => Ok(Ok(posted)),
            Err(refusal) => Ok(Err(refusal)),
            Ok(None) => Ok(Err(plan_invalidated(
                "publication did not retain the exact batch plan",
            ))),
        },
        Err(refusal) if refusal.exit == exit::CONFLICT => {
            Ok(Err(plan_invalidated(refusal.message)))
        }
        Err(refusal) => Ok(Err(refusal)),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use asupersync::Budget;
    use asupersync::runtime::RuntimeBuilder;
    use fgdb::{DatabaseKeys, MemVfs};
    use fgdb_types::ids::DatabaseSecurityNamespaceId;

    #[test]
    fn outcome_body_bytes_are_fixed_and_round_trip() {
        let body = OutcomeBody {
            request_digest: [7; 32],
            entries: vec![
                EntryRef {
                    vid: VId(1),
                    entry_digest: [2; 32],
                },
                EntryRef {
                    vid: VId(3),
                    entry_digest: [4; 32],
                },
            ],
        };
        let bytes = body.canonical_bytes().unwrap();
        let mut expected = b"FA-OUTCOME\0".to_vec();
        expected.extend_from_slice(&[1, 0, 0, 0, 1]);
        expected.extend_from_slice(&[7; 32]);
        expected.extend_from_slice(&2_u32.to_le_bytes());
        for (vid, digest) in [(1_u128, 2_u8), (3, 4)] {
            expected.extend_from_slice(&vid.to_le_bytes());
            expected.extend_from_slice(&[digest; 32]);
        }
        assert_eq!(bytes, expected);
        assert_eq!(OutcomeBody::decode(&bytes).unwrap(), body);
        for end in 0..bytes.len() {
            assert!(OutcomeBody::decode(&bytes[..end]).is_err(), "prefix {end}");
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(OutcomeBody::decode(&trailing).is_err());
        let mut kind = bytes;
        kind[15] = 2;
        assert!(OutcomeBody::decode(&kind).is_err());
    }

    #[test]
    fn maximum_outcome_survives_reopen_and_rejects_fragment_corruption() {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let vfs = cx.commit().with_restriction(MemVfs::new).unwrap();
        let keys = DatabaseKeys::new([41; 32], DatabaseSecurityNamespaceId([42; 32]), [43; 32]);
        let path = vfs.database_dir();
        let mut db = runtime
            .block_on(Database::create_with_vfs(
                &cx.commit(),
                vfs.clone(),
                &path,
                keys.clone(),
            ))
            .unwrap();
        let body = OutcomeBody {
            request_digest: [44; 32],
            entries: (0..fa_model::limits::MAX_BATCH_ENTRIES)
                .map(|index| EntryRef {
                    vid: VId(index as u128 + 10),
                    entry_digest: [45; 32],
                })
                .collect(),
        };
        assert_eq!(body.canonical_bytes().unwrap().len(), MAX_OUTCOME_BYTES);
        let book = Id128([46; 16]);
        let vid = VId(1);
        let mut stage = WriteBatch::new(relation::IN_BATCH);
        stage_outcome(&cx.query(), &mut stage, book, vid, &body).unwrap();
        assert!(read_outcome(&db, &cx.query(), vid).unwrap().is_none());
        let seq = runtime.block_on(db.write(&cx.commit(), stage)).unwrap();
        assert_eq!(
            db.vertices().unwrap().len(),
            1 + MAX_OUTCOME_BYTES.div_ceil(object::CHUNK_BYTES)
        );
        drop(db);
        let mut db = runtime
            .block_on(Database::open_with_vfs(&cx.commit(), vfs, &path, keys))
            .unwrap();
        assert!(matches!(
            db.delta_since(CommitSeq(0)),
            Err(fgdb::ReadError::DeltaCursorRetired { .. })
        ));
        assert_eq!(
            read_outcome(&db, &cx.query(), vid).unwrap(),
            Some((body.clone(), seq))
        );
        assert!(matches!(
            db.delta_since(CommitSeq(0)),
            Err(fgdb::ReadError::DeltaCursorRetired { .. })
        ));

        // A legacy raw scalar above the current inline threshold remains valid.
        let legacy = OutcomeBody {
            entries: body.entries[..90].to_vec(),
            ..body
        };
        let legacy_bytes = legacy.canonical_bytes().unwrap();
        assert!(legacy_bytes.len() > object::CHUNK_BYTES);
        let mut stage = WriteBatch::new(relation::IN_BATCH);
        stage.create_vertex(
            VId(2),
            vec![label::INTENT_OUTCOME],
            vec![(
                property::FA_PAYLOAD,
                scalar_bytes("legacy outcome", legacy_bytes).unwrap(),
            )],
        );
        let legacy_seq = runtime.block_on(db.write(&cx.commit(), stage)).unwrap();
        assert_eq!(
            read_outcome(&db, &cx.query(), VId(2)).unwrap(),
            Some((legacy, legacy_seq))
        );

        let fragment = db
            .vertices()
            .unwrap()
            .into_iter()
            .find(|row| row.labels.as_slice() == [label::INTENT_OUTCOME] && row.props.len() == 3)
            .unwrap();
        let mut damaged = crate::rows::bytes(&fragment, property::FA_PAYLOAD, "fragment").unwrap();
        damaged[0] ^= 1;
        let mut corruption = WriteBatch::new(relation::IN_BATCH);
        corruption.set_vertex_property(
            fragment.vid,
            property::FA_PAYLOAD,
            Some(scalar_bytes("corruption", damaged).unwrap()),
        );
        runtime
            .block_on(db.write(&cx.commit(), corruption))
            .unwrap();
        assert!(matches!(
            read_outcome(&db, &cx.query(), vid),
            Err(KernelError::Corrupt(_))
        ));
    }

    pub(crate) fn setup_batch_test_book() -> (
        asupersync::runtime::Runtime,
        asupersync::Cx,
        Database<MemVfs>,
        BookContext,
        fa_money::UnitId,
        VId,
        VId,
        Vec<fa_model::EvidenceRef>,
    ) {
        use fa_model::{Erasable, SealKey, SymbolTable, account_vid};
        use fa_money::UnitRegistry;
        use fa_time::{DateDay, FiscalCalendar, PeriodKind, PeriodTransition};

        let runtime = RuntimeBuilder::new().build().expect("runtime");
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let ctx = PurposeContexts::narrow_runtime_root(&root);
        let keys = DatabaseKeys::new(
            [0x6a; 32],
            DatabaseSecurityNamespaceId([0x6b; 32]),
            [0x6c; 32],
        );
        let mut db = runtime
            .block_on(async { Database::open_memory(&ctx.commit(), keys).await })
            .expect("open");
        let units = UnitRegistry::with_defaults();
        let usd = units.lookup("USD").expect("USD");
        let calendar = FiscalCalendar::monthly("cal", 1, 1).expect("calendar");
        let book_id = Id128([0x19; 16]);
        let spec = crate::genesis::BookSpec {
            book_id,
            name: "Batch Budget Co".into(),
            base_unit: usd,
            calendar: calendar.clone(),
            time_zone_policy: Some(crate::genesis::TimeZonePolicy::Utc),
            entities: Vec::new(),
            opening_date: None,
        };
        let symbols = SymbolTable::compiled();
        runtime
            .block_on(async {
                crate::genesis::create_book(&mut db, &ctx, &spec, &units, &symbols).await
            })
            .expect("create_book");
        let book = BookContext {
            book_id,
            calendar,
            units,
            seal_key: SealKey([0x11; 32]),
            symbols,
        };
        let principal = VId(7);
        let chart = vec![
            crate::genesis::AccountSpec {
                code: "1000".into(),
                name: "Cash".into(),
                account_type: 1,
                normal_balance: 0,
                is_leaf: true,
                unit_policy: crate::genesis::UnitPolicy::Single(usd),
                parent_code: None,
                limit: None,
            },
            crate::genesis::AccountSpec {
                code: "6000".into(),
                name: "Rent".into(),
                account_type: 5,
                normal_balance: 0,
                is_leaf: true,
                unit_policy: crate::genesis::UnitPolicy::Single(usd),
                parent_code: None,
                limit: None,
            },
        ];
        let day = DateDay::from_ymd(2026, 3, 15).expect("day");
        let schema_cap = Capability::embedded(principal, &["schema_change"]).expect("cap");
        runtime
            .block_on(async {
                crate::genesis::install_chart(
                    &mut db,
                    &ctx,
                    &book,
                    &chart,
                    principal,
                    day,
                    b"chart-1",
                    Erasable::seal(&"chart".to_string(), None, &book.seal_key, [5; 32], [6; 24]),
                    &schema_cap,
                )
                .await
            })
            .expect("install_chart")
            .expect("admitted");
        let (_, periods) = runtime
            .block_on(async {
                crate::genesis::create_periods(
                    &mut db,
                    &ctx,
                    &book,
                    2026,
                    principal,
                    Erasable::seal(
                        &"periods".to_string(),
                        None,
                        &book.seal_key,
                        [1; 32],
                        [2; 24],
                    ),
                    &schema_cap,
                )
                .await
            })
            .expect("create_periods")
            .expect("admitted");
        let march = periods
            .iter()
            .find(|p| p.contains(day) && p.kind == PeriodKind::Normal)
            .expect("march")
            .code
            .clone();
        let doc = crate::evidence::Document {
            book_id,
            kind: 1,
            mime: "text/plain".into(),
            grade: 3,
            retrieved_by: principal,
            bytes: b"INVOICE 2026-0315 Batch Budget Co fixture source document".to_vec(),
        };
        runtime
            .block_on(async { crate::evidence::add_document(&mut db, &ctx, &book, &doc).await })
            .expect("add_document")
            .expect("admitted");
        let evidence = vec![doc.evidence_ref(1)];
        let open_cap = Capability::embedded(principal, &["close"]).expect("cap");
        runtime
            .block_on(async {
                crate::period::transition_period(
                    &mut db,
                    &ctx,
                    &book,
                    &march,
                    PeriodTransition::Open,
                    principal,
                    1,
                    b"open-march",
                    Erasable::seal(&"open".to_string(), None, &book.seal_key, [3; 32], [4; 24]),
                    &open_cap,
                    &[],
                )
                .await
            })
            .expect("open")
            .expect("admitted");

        (
            runtime,
            root,
            db,
            book,
            usd,
            account_vid(book_id, "1000"),
            account_vid(book_id, "6000"),
            evidence,
        )
    }

    pub(crate) fn make_entry_intent(
        book: &BookContext,
        usd: fa_money::UnitId,
        cash: VId,
        rent: VId,
        evidence: &[fa_model::EvidenceRef],
        leg_pairs: usize,
        key: &[u8],
    ) -> fa_intents::PostIntent {
        use fa_model::{EntryClass, EntryOrigin, EntryPayload, Erasable, LegPayload, Oid};
        use fa_money::{Amount, Side};
        use fa_time::DateDay;

        let mut legs = Vec::with_capacity(leg_pairs * 2);
        for _ in 0..leg_pairs {
            legs.push(LegPayload::simple(
                Side::Debit,
                rent,
                Amount::new(usd, 1_000),
            ));
            legs.push(LegPayload::simple(
                Side::Credit,
                cash,
                Amount::new(usd, 1_000),
            ));
        }
        let unit_totals = EntryPayload::fold_unit_totals(&legs).expect("totals");
        fa_intents::PostIntent::new(
            EntryPayload {
                schema_minor: 0,
                book_id: book.book_id,
                branch_id: Id128::TRUNK,
                class: EntryClass::ORIGINAL,
                effective_date: DateDay::from_ymd(2026, 3, 15).expect("day"),
                document_date: None,
                description: Erasable::seal(
                    &"batch member".to_string(),
                    None,
                    &book.seal_key,
                    [0x22; 32],
                    [0x33; 24],
                ),
                effective_period: None,
                legs,
                control: None,
                unit_totals,
                base_totals: None,
                idempotency_key: key.to_vec(),
                origin: EntryOrigin::Intent {
                    intent_oid: Oid([1; 32]),
                    intent_kind: 1,
                },
                principal_ref: VId(7),
                session_ref: None,
                evidence: evidence.to_vec(),
                supersession: Vec::new(),
                pending: None,
                external_ids: Vec::new(),
                extensions: Vec::new(),
                tags: Vec::new(),
            },
            Vec::new(),
        )
        .expect("intent")
    }

    #[test]
    fn template_byte_tracker_matches_substrate_canonical_delta_bytes() {
        let (runtime, root, mut db, book, usd, cash, rent, evidence) = setup_batch_test_book();
        let ctx = PurposeContexts::narrow_runtime_root(&root);
        let cap = Capability::embedded(VId(7), &["post"]).expect("post cap");
        let batch = PostBatch::new(
            b"exact-byte-check".to_vec(),
            vec![
                make_entry_intent(&book, usd, cash, rent, &evidence, 1, b"m-0"),
                make_entry_intent(&book, usd, cash, rent, &evidence, 3, b"m-1"),
                make_entry_intent(&book, usd, cash, rent, &evidence, 5, b"m-2"),
            ],
        )
        .expect("batch");
        let basis = db.frontier().expect("frontier");
        let staged = match stage_batch(
            &mut db,
            &ctx,
            &book,
            &vec![cap.clone(); 3],
            &batch,
            Admission::Commit,
        )
        .expect("kernel")
        .expect("admitted")
        {
            BatchStage::Staged(staged) => staged,
            BatchStage::Recorded(_) => panic!("expected fresh staged batch"),
        };
        let tracked_template_bytes = staged.template_tracker.total_bytes();
        let posted = runtime
            .block_on(commit_batch(
                &mut db,
                &ctx,
                &book,
                &vec![cap; 3],
                &batch,
                Admission::Commit,
                staged,
            ))
            .expect("kernel")
            .expect("committed");
        assert!(!posted.already_recorded);
        let deltas: Vec<_> = db.delta_since(basis).expect("delta_since").collect();
        assert_eq!(deltas.len(), 1);
        // LogicalDeltaBatch canonical encoding adds 8 bytes (CommitSeq) + 16 bytes (WriteId)
        // to the LogicalDeltaTemplate canonical bytes.
        assert_eq!(
            deltas[0].canonical_bytes().expect("canonical_bytes").len(),
            tracked_template_bytes + 24
        );
    }

    #[test]
    fn template_byte_tracker_rewrites_match_every_native_transaction_prefix() {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let ctx = PurposeContexts::narrow_runtime_root(&root);
        let bytes = |len| scalar_bytes("tracker fixture", vec![42; len]).unwrap();
        let edits = [
            (
                relation::IN_BATCH,
                VId(1),
                property::GENERATION,
                Some(CanonicalScalar::Int(7)),
            ),
            (
                relation::IN_BATCH,
                VId(1),
                property::GENERATION,
                Some(CanonicalScalar::Int(8)),
            ),
            (
                relation::IN_BATCH,
                VId(2),
                property::GENERATION,
                Some(CanonicalScalar::Int(9)),
            ),
            // Both net rows disappear; the empty IN_BATCH frame remains.
            (
                relation::IN_BATCH,
                VId(1),
                property::GENERATION,
                Some(CanonicalScalar::Int(7)),
            ),
            (
                relation::IN_BATCH,
                VId(2),
                property::GENERATION,
                Some(CanonicalScalar::Int(7)),
            ),
            (relation::IN_BATCH, VId(1), property::GENERATION, None),
            (
                relation::IN_BATCH,
                VId(1),
                property::GENERATION,
                Some(bytes(32)),
            ),
            (
                relation::IN_BATCH,
                VId(1),
                property::GENERATION,
                Some(CanonicalScalar::Int(7)),
            ),
            // Returning this property to absence must retain the fixed edge.
            (
                relation::POSTS_TO,
                VId(1),
                property::TARGET_REF,
                Some(bytes(8)),
            ),
            (relation::POSTS_TO, VId(1), property::TARGET_REF, None),
            // Updates fold into the creation, but still introduce IN_BOOK.
            (
                relation::IN_BOOK,
                VId(3),
                property::FA_PAYLOAD,
                Some(bytes(64)),
            ),
            (relation::IN_BOOK, VId(3), property::FA_PAYLOAD, None),
            (
                relation::IN_BOOK,
                VId(3),
                property::TARGET_REF,
                Some(bytes(9)),
            ),
            (
                relation::IN_BOOK,
                VId(3),
                property::TARGET_REF,
                Some(bytes(7)),
            ),
            (relation::IN_BOOK, VId(3), property::TARGET_REF, None),
            // Removing an update cannot remove a relation with a created row.
            (
                relation::HAS_LEG,
                VId(1),
                property::FA_PAYLOAD,
                Some(bytes(7)),
            ),
            (relation::HAS_LEG, VId(1), property::FA_PAYLOAD, None),
            (
                relation::HAS_LEG,
                VId(1),
                property::FA_PAYLOAD,
                Some(bytes(9)),
            ),
        ];
        for prefix in 0..=edits.len() {
            let mut db = runtime
                .block_on(Database::open_memory(
                    &ctx.commit(),
                    DatabaseKeys::new([81; 32], DatabaseSecurityNamespaceId([82; 32]), [83; 32]),
                ))
                .unwrap();
            let mut seed = WriteBatch::new(relation::IN_BOOK);
            for vid in [VId(1), VId(2)] {
                seed.create_vertex(
                    vid,
                    vec![label::ACCOUNT],
                    vec![
                        (property::GENERATION, CanonicalScalar::Int(7)),
                        (property::FA_PAYLOAD, bytes(9)),
                    ],
                );
            }
            runtime.block_on(db.write(&ctx.commit(), seed)).unwrap();
            let basis = db.frontier().unwrap();
            let mut txn = db.begin(&ctx.txn()).unwrap();
            let mut tracker = TemplateByteTracker::default();
            let props = vec![(property::FA_PAYLOAD, bytes(7))];
            let mut created = WriteBatch::new(relation::HAS_LEG);
            created.create_vertex(VId(3), vec![label::ACCOUNT], props.clone());
            tracker.create_vertex(relation::HAS_LEG, VId(3), 1, &props);
            let mut edge = WriteBatch::new(relation::POSTS_TO);
            edge.add_edge(fgdb_types::EId(4), VId(3), VId(1), vec![]);
            tracker.add_edge(relation::POSTS_TO, &[]);
            txn.write_ordered(&mut db, vec![created, edge]).unwrap();
            for (relation, vid, key, after) in &edits[..prefix] {
                let before = txn.vertex_property(&db, *vid, *key).unwrap();
                tracker.set_vertex_property(*relation, *vid, *key, before, after.clone());
                let mut stage = WriteBatch::new(*relation);
                stage.set_vertex_property(*vid, *key, after.clone());
                txn.write_ordered(&mut db, vec![stage]).unwrap();
            }
            runtime
                .block_on(txn.commit(&mut db, &ctx.commit()))
                .unwrap();
            let deltas: Vec<_> = db.delta_since(basis).unwrap().collect();
            assert_eq!(deltas.len(), 1, "prefix {prefix}");
            assert_eq!(
                tracker.total_bytes() + 24,
                deltas[0].canonical_bytes().unwrap().len(),
                "prefix {prefix}: coalesced rows and relation framing must match the substrate",
            );
        }
    }

    #[test]
    fn template_byte_tracker_empty_rewrites_and_replaced_vertices_keep_coordinate_framing() {
        let mut tracker = TemplateByteTracker::default();
        assert_eq!(tracker.total_bytes(), 0);
        let set = |tracker: &mut TemplateByteTracker, before, after| {
            tracker.set_vertex_property(
                relation::IN_BOOK,
                VId(1),
                property::GENERATION,
                Some(CanonicalScalar::Int(before)),
                Some(CanonicalScalar::Int(after)),
            );
        };
        set(&mut tracker, 7, 7);
        let empty_coordinate = 70 + 53;
        assert_eq!(tracker.total_bytes(), empty_coordinate);
        set(&mut tracker, 7, 8);
        let changed = tracker.total_bytes();
        assert!(changed > 0);
        set(&mut tracker, 8, 7);
        assert_eq!(tracker.total_bytes(), empty_coordinate);
        set(&mut tracker, 7, 9);
        assert_eq!(tracker.total_bytes(), changed);
        set(&mut tracker, 9, 7);
        assert_eq!(tracker.total_bytes(), empty_coordinate);

        let mut tracker = TemplateByteTracker::default();
        tracker.create_vertex_lens(relation::HAS_LEG, VId(2), 2, [(property::FA_PAYLOAD, 100)]);
        tracker.create_vertex_lens(relation::POSTS_TO, VId(3), 1, []);
        tracker.create_vertex_lens(relation::POSTS_TO, VId(2), 0, [(property::GENERATION, 9)]);
        let mut final_rows = TemplateByteTracker::default();
        final_rows.create_vertex(relation::POSTS_TO, VId(3), 1, &[]);
        final_rows.create_vertex(
            relation::POSTS_TO,
            VId(2),
            0,
            &[(property::GENERATION, CanonicalScalar::Int(9))],
        );
        assert_eq!(tracker.total_bytes(), final_rows.total_bytes() + 53);
        assert_eq!(tracker.relations.len(), 2);
    }

    #[test]
    fn template_byte_tracker_matches_inline_and_chunked_outcome_bytes() {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let ctx = PurposeContexts::narrow_runtime_root(&root);
        let inline_members = (object::CHUNK_BYTES - 52) / 48;
        for members in [
            inline_members,
            inline_members + 1,
            fa_model::limits::MAX_BATCH_ENTRIES,
        ] {
            let mut db = runtime
                .block_on(Database::open_memory(
                    &ctx.commit(),
                    DatabaseKeys::new([84; 32], DatabaseSecurityNamespaceId([85; 32]), [86; 32]),
                ))
                .unwrap();
            let body = OutcomeBody {
                request_digest: [87; 32],
                entries: (0..members)
                    .map(|i| EntryRef {
                        vid: VId(i as u128 + 10),
                        entry_digest: [88; 32],
                    })
                    .collect(),
            };
            let mut stage = WriteBatch::new(relation::IN_BATCH);
            let mut tracker = TemplateByteTracker::default();
            stage_outcome_tracked(
                &ctx.query(),
                &mut stage,
                &mut tracker,
                Id128([89; 16]),
                VId(1),
                &body,
            )
            .unwrap();
            let basis = db.frontier().unwrap();
            runtime.block_on(db.write(&ctx.commit(), stage)).unwrap();
            let deltas: Vec<_> = db.delta_since(basis).unwrap().collect();
            assert_eq!(deltas.len(), 1);
            assert_eq!(
                tracker.total_bytes() + 24,
                deltas[0].canonical_bytes().unwrap().len(),
                "{members} members: all fragment rows and one relation frame must be counted",
            );
        }
    }

    #[test]
    fn template_byte_tracker_checks_one_hundred_thousand_staged_rows() {
        // Query after every mutation, as batch admission does. Recounting the
        // growing prefix makes this fixture quadratic even without storage.
        // This exercises only byte accounting, not a larger permitted batch.
        const ROWS: usize = 100_000;
        let mut tracker = TemplateByteTracker::default();
        let scalar = CanonicalScalar::Int(7);
        let scalar_len = scalar.encode().unwrap().len();
        let vertex_bytes = 38 + 8 + 12 + scalar_len;
        let update_bytes = 30 + 2 * (5 + scalar_len);
        for i in 0..ROWS {
            tracker.create_vertex(
                relation::HAS_LEG,
                VId(i as u128),
                1,
                &[(property::GENERATION, scalar.clone())],
            );
            let relations = if i == 0 { 1 } else { 2 };
            assert_eq!(
                tracker.total_bytes(),
                70 + 53 * relations + vertex_bytes * (i + 1) + update_bytes * i,
                "after creation {i}",
            );
            tracker.set_vertex_property(
                relation::IN_BOOK,
                VId((ROWS + i) as u128),
                property::GENERATION,
                Some(scalar.clone()),
                Some(CanonicalScalar::Int(8)),
            );
            assert_eq!(
                tracker.total_bytes(),
                70 + 2 * 53 + (vertex_bytes + update_bytes) * (i + 1),
                "after update {i}",
            );
        }
        for remaining in (0..ROWS).rev() {
            tracker.set_vertex_property(
                relation::IN_BOOK,
                VId((ROWS + remaining) as u128),
                property::GENERATION,
                Some(CanonicalScalar::Int(8)),
                Some(scalar.clone()),
            );
            assert_eq!(
                tracker.total_bytes(),
                70 + 2 * 53 + vertex_bytes * ROWS + update_bytes * remaining,
                "after restoring update {remaining}",
            );
        }
    }

    fn assert_template_trackers_equal(
        actual: &TemplateByteTracker,
        expected: &TemplateByteTracker,
    ) {
        assert_eq!(actual.total_bytes(), expected.total_bytes());
        assert_eq!(actual.relations, expected.relations);
        assert_eq!(actual.row_bytes, expected.row_bytes);
        assert_eq!(actual.created_vertices, expected.created_vertices);
        assert_eq!(actual.property_updates, expected.property_updates);
    }

    #[test]
    fn template_byte_checkpoints_match_cloned_candidates_for_every_admission_history() {
        const CANDIDATES: usize = 8;
        let bytes = |len| scalar_bytes("checkpoint fixture", vec![42; len]).unwrap();
        let chunked = vec![42; object::CHUNK_BYTES + 1];
        let apply = |tracker: &mut TemplateByteTracker, candidate: usize, edit: usize| {
            let vid = VId(10 + candidate as u128);
            let shared = VId(1);
            let existing = VId(2);
            let changed = VId(100 + candidate as u128);
            match edit {
                0 => tracker.create_vertex(
                    relation::HAS_LEG,
                    vid,
                    1,
                    &[(property::FA_PAYLOAD, bytes(7))],
                ),
                1 => tracker.set_vertex_property(
                    relation::IN_BOOK,
                    vid,
                    property::FA_PAYLOAD,
                    Some(bytes(7)),
                    Some(bytes(17)),
                ),
                2 => tracker.set_vertex_property(
                    relation::IN_BOOK,
                    vid,
                    property::FA_PAYLOAD,
                    Some(bytes(17)),
                    None,
                ),
                3 => tracker.set_vertex_property(
                    relation::IN_BOOK,
                    vid,
                    property::GENERATION,
                    None,
                    Some(CanonicalScalar::Int(7)),
                ),
                4 => tracker.set_vertex_property(
                    relation::IN_BOOK,
                    shared,
                    property::FA_PAYLOAD,
                    Some(bytes(7)),
                    Some(bytes(candidate + 9)),
                ),
                5..=7 => tracker.set_vertex_property(
                    relation::IN_BOOK,
                    existing,
                    property::GENERATION,
                    Some(CanonicalScalar::Int(9)),
                    match edit {
                        5 => Some(CanonicalScalar::Int(7)),
                        6 => None,
                        _ => Some(CanonicalScalar::Int(10 + candidate as i64)),
                    },
                ),
                8 | 9 => tracker.set_vertex_property(
                    relation::IN_BATCH,
                    changed,
                    property::TARGET_REF,
                    None,
                    (edit == 8).then(|| bytes(8)),
                ),
                10 => tracker.add_edge(
                    relation::IN_UNIT,
                    &[(property::ORDINAL, CanonicalScalar::Int(2))],
                ),
                11 => tracker.record_object_stage(relation::FOR, &chunked),
                // Replacement and subsequent property edits must preserve the
                // first snapshot, rather than overwrite it with an intermediate.
                12 => tracker.create_vertex(
                    relation::HAS_LEG,
                    shared,
                    2,
                    &[(property::FA_PAYLOAD, bytes(32))],
                ),
                13 => tracker.set_vertex_property(
                    relation::IN_BOOK,
                    shared,
                    property::FA_PAYLOAD,
                    Some(bytes(32)),
                    Some(bytes(63)),
                ),
                14 => tracker.create_vertex(
                    relation::HAS_LEG,
                    shared,
                    1,
                    &[(property::FA_PAYLOAD, bytes(candidate + 9))],
                ),
                15 => tracker.set_vertex_property(
                    relation::EVIDENCED_BY,
                    changed,
                    property::GENERATION,
                    None,
                    None,
                ),
                _ => unreachable!("fixture edit"),
            }
        };
        for accepted in 0..(1 << CANDIDATES) {
            let mut tracker = TemplateByteTracker::default();
            tracker.create_vertex(
                relation::HAS_LEG,
                VId(1),
                1,
                &[(property::FA_PAYLOAD, bytes(7))],
            );
            tracker.set_vertex_property(
                relation::IN_BOOK,
                VId(2),
                property::GENERATION,
                Some(CanonicalScalar::Int(7)),
                Some(CanonicalScalar::Int(9)),
            );
            let mut baseline = tracker.clone();
            for candidate in 0..CANDIDATES {
                // The previous admission strategy cloned the accepted prefix
                // and discarded that clone on refusal or a full byte budget.
                let mut cloned_candidate = baseline.clone();
                {
                    let mut checkpoint = tracker.checkpoint();
                    for edit in 0..16 {
                        apply(&mut cloned_candidate, candidate, edit);
                        apply(&mut checkpoint, candidate, edit);
                        assert_template_trackers_equal(&checkpoint, &cloned_candidate);
                    }
                    if accepted & (1 << candidate) != 0 {
                        checkpoint.commit();
                        baseline = cloned_candidate;
                    }
                }
                assert!(tracker.undo.is_none());
                assert_template_trackers_equal(&tracker, &baseline);
            }
        }
    }

    #[test]
    fn template_byte_checkpoint_restores_errors_and_rejects_nested_checkpoints() {
        let mut tracker = TemplateByteTracker::default();
        tracker.create_vertex(
            relation::HAS_LEG,
            VId(1),
            1,
            &[(property::GENERATION, CanonicalScalar::Int(7))],
        );
        let baseline = tracker.clone();
        let result = (|| -> Result<(), &'static str> {
            let mut candidate = tracker.checkpoint();
            candidate.set_vertex_property(
                relation::IN_BOOK,
                VId(1),
                property::GENERATION,
                Some(CanonicalScalar::Int(7)),
                None,
            );
            candidate.add_edge(relation::IN_BATCH, &[]);
            let admission: Result<(), _> = Err("candidate refused");
            admission?;
            candidate.commit();
            Ok(())
        })();
        assert_eq!(result, Err("candidate refused"));
        assert_template_trackers_equal(&tracker, &baseline);
        assert!(tracker.undo.is_none());

        let nested = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut candidate = tracker.checkpoint();
            candidate.add_edge(relation::IN_BATCH, &[]);
            let _nested = candidate.checkpoint();
        }));
        let panic = nested.expect_err("nested checkpoints must be rejected");
        let message = panic
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| panic.downcast_ref::<String>().map(String::as_str));
        assert_eq!(message, Some("nested template byte checkpoints"),);
        assert_template_trackers_equal(&tracker, &baseline);
        assert!(tracker.undo.is_none());

        // A copied speculative view has no borrowed rollback responsibility.
        // Its own checkpoint cannot discard the original guard's undo log.
        let mut candidate = tracker.checkpoint();
        candidate.add_edge(relation::IN_BATCH, &[]);
        let mut independent = (*candidate).clone();
        let speculative_bytes = independent.total_bytes();
        {
            let mut independent_candidate = independent.checkpoint();
            independent_candidate.add_edge(relation::IN_UNIT, &[]);
        }
        assert_eq!(independent.total_bytes(), speculative_bytes);
        drop(candidate);
        assert_template_trackers_equal(&tracker, &baseline);
        independent.checkpoint().commit();
        assert_eq!(independent.total_bytes(), speculative_bytes);
    }

    #[test]
    fn template_byte_checkpoints_admit_one_hundred_thousand_members_without_prefix_copies() {
        // This is a tracker complexity fixture, not an increase to the native
        // transaction limit. Every candidate changes two created vertices and
        // two property updates, regardless of the accepted prefix's size.
        const MEMBERS: usize = 100_000;
        let mut tracker = TemplateByteTracker::default();
        let original = CanonicalScalar::Int(7);
        let scalar_len = original.encode().unwrap().len();
        let vertex_bytes = 38 + 8 + 12 + scalar_len;
        let update_bytes = 30 + 2 * (5 + scalar_len);
        let shared_created = VId((2 * MEMBERS + 1) as u128);
        let shared_existing = VId((2 * MEMBERS + 2) as u128);
        tracker.create_vertex(
            relation::HAS_LEG,
            shared_created,
            1,
            &[(property::GENERATION, original.clone())],
        );
        tracker.set_vertex_property(
            relation::IN_BOOK,
            shared_existing,
            property::GENERATION,
            Some(original.clone()),
            Some(CanonicalScalar::Int(8)),
        );
        let mut accepted = 0;
        let expanded = scalar_bytes("checkpoint size change", vec![42; 17]).unwrap();
        for member in 0..MEMBERS {
            let before_bytes = tracker.total_bytes();
            let before_relations = tracker.relations.len();
            let mut candidate = tracker.checkpoint();
            candidate.create_vertex(
                relation::HAS_LEG,
                VId((member + 1) as u128),
                1,
                &[(property::GENERATION, original.clone())],
            );
            candidate.set_vertex_property(
                relation::IN_BOOK,
                shared_existing,
                property::GENERATION,
                Some(CanonicalScalar::Int(8)),
                Some(original.clone()),
            );
            assert_eq!(
                candidate.total_bytes(),
                before_bytes + vertex_bytes - update_bytes,
            );
            candidate.set_vertex_property(
                relation::IN_BOOK,
                shared_existing,
                property::GENERATION,
                Some(original.clone()),
                Some(CanonicalScalar::Int(8)),
            );
            for after in [Some(expanded.clone()), None] {
                candidate.set_vertex_property(
                    relation::IN_BOOK,
                    shared_created,
                    property::FA_PAYLOAD,
                    None,
                    after,
                );
            }
            for after in [CanonicalScalar::Int(8), original.clone()] {
                candidate.set_vertex_property(
                    relation::IN_BATCH,
                    VId((MEMBERS + member + 1) as u128),
                    property::GENERATION,
                    Some(original.clone()),
                    Some(after),
                );
            }
            candidate.add_edge(relation::FOR, &[]);
            assert_eq!(
                candidate.total_bytes(),
                before_bytes
                    + vertex_bytes
                    + 75
                    + 53 * (candidate.relations.len() - before_relations),
            );
            let undo = candidate.undo.as_ref().unwrap();
            assert_eq!(undo.created_vertices.len(), 2);
            assert_eq!(undo.property_updates.len(), 2);
            assert!(undo.new_relations.len() <= 2);
            assert_eq!(
                undo.property_updates
                    .get(&(shared_existing, property::GENERATION)),
                Some(&Some(update_bytes)),
            );
            if member.is_multiple_of(3) {
                drop(candidate);
            } else {
                candidate.commit();
                accepted += 1;
            }
            let relations = if accepted == 0 { 2 } else { 4 };
            assert_eq!(
                tracker.total_bytes(),
                70 + 53 * relations + vertex_bytes * (accepted + 1) + update_bytes + 75 * accepted,
            );
            assert_eq!(tracker.created_vertices.len(), accepted + 1);
            assert_eq!(tracker.property_updates.len(), accepted + 1);
            assert!(tracker.undo.is_none());
        }
    }

    #[test]
    fn batch_exceeding_v1_capsule_ceiling_refuses_with_fa_ref_201_and_split_bound() {
        let (runtime, root, mut db, book, usd, cash, rent, evidence) = setup_batch_test_book();
        let ctx = PurposeContexts::narrow_runtime_root(&root);
        let cap = Capability::embedded(VId(7), &["post"]).expect("post cap");

        // Each 240-leg (120 debit/credit pair) entry is ~13.3 KB in vertex storage
        // (< 16,384 B per-vertex limit), but contributes ~126 KB to LogicalDeltaTemplate.
        // Measure the exact 1-entry and 2-entry template footprints to find the exact
        // boundary count N where N entries fit <= MAX_BATCH_TEMPLATE_BYTES and N + 1 exceed it.
        let probe_batch = PostBatch::new(
            b"probe-batch".to_vec(),
            vec![
                make_entry_intent(&book, usd, cash, rent, &evidence, 120, b"probe-000"),
                make_entry_intent(&book, usd, cash, rent, &evidence, 120, b"probe-001"),
            ],
        )
        .expect("probe batch");
        let two_entry_bytes = match stage_batch(
            &mut db,
            &ctx,
            &book,
            &vec![cap.clone(); 2],
            &probe_batch,
            Admission::Plan,
        )
        .expect("kernel")
        .expect("probe staged")
        {
            BatchStage::Staged(staged) => {
                let bytes = staged.template_tracker.total_bytes();
                staged.txn.abort();
                bytes
            }
            BatchStage::Recorded(_) => panic!("expected fresh probe"),
        };
        let one_probe = PostBatch::new(
            b"probe-batch-1".to_vec(),
            vec![make_entry_intent(
                &book,
                usd,
                cash,
                rent,
                &evidence,
                120,
                b"probe-000",
            )],
        )
        .expect("probe 1");
        let one_entry_bytes = match stage_batch(
            &mut db,
            &ctx,
            &book,
            std::slice::from_ref(&cap),
            &one_probe,
            Admission::Plan,
        )
        .expect("kernel")
        .expect("probe 1 staged")
        {
            BatchStage::Staged(staged) => {
                let bytes = staged.template_tracker.total_bytes();
                staged.txn.abort();
                bytes
            }
            BatchStage::Recorded(_) => panic!("expected fresh probe 1"),
        };
        let per_additional_entry = two_entry_bytes - one_entry_bytes;
        let fit_count = 1
            + (fa_model::limits::MAX_BATCH_TEMPLATE_BYTES - one_entry_bytes) / per_additional_entry;
        let over_count = fit_count + 1;
        assert!(
            over_count < 200_usize.min(fa_model::limits::MAX_BATCH_ENTRIES),
            "over_count={over_count} must be well below MAX_BATCH_ENTRIES"
        );

        let over_entries: Vec<fa_intents::PostIntent> = (0..over_count)
            .map(|i| {
                make_entry_intent(
                    &book,
                    usd,
                    cash,
                    rent,
                    &evidence,
                    120,
                    format!("over-{i:03}").as_bytes(),
                )
            })
            .collect();
        let over_batch =
            PostBatch::new(b"over-capsule-batch".to_vec(), over_entries).expect("batch");
        let basis = db.frontier().expect("frontier");

        let plan_refusal = plan_batch(&mut db, &ctx, &book, cap.clone(), over_batch.clone())
            .expect("kernel")
            .expect_err("over-budget batch plan must refuse");
        assert_eq!(plan_refusal.code, code::BATCH_BYTE_BUDGET);
        assert_eq!(plan_refusal.exit, exit::REFUSAL);

        let commit_refusal = runtime
            .block_on(post_batch(&mut db, &ctx, &book, cap.clone(), over_batch))
            .expect("kernel")
            .expect_err("over-budget batch commit must refuse");
        assert_eq!(commit_refusal.code, code::BATCH_BYTE_BUDGET);
        assert_eq!(commit_refusal.exit, exit::REFUSAL);
        let detail = commit_refusal.detail.as_ref().expect("detail");
        assert!(
            detail
                .at
                .contains(&("member", crate::refusal::Locus::Index(fit_count as u64))),
            "at: {:?}",
            detail.at
        );
        assert!(
            detail.at.contains(&(
                "max_batch_template_bytes",
                crate::refusal::Locus::Index(fa_model::limits::MAX_BATCH_TEMPLATE_BYTES as u64),
            )),
            "at: {:?}",
            detail.at
        );
        assert!(
            detail
                .at
                .contains(&("recommended_splits", crate::refusal::Locus::Index(2))),
            "at: {:?}",
            detail.at
        );
        assert_eq!(
            db.frontier().expect("frontier"),
            basis,
            "refused batch must leave book head unchanged"
        );

        // fit_count such entries fit <= MAX_BATCH_TEMPLATE_BYTES (14,439,152 B)
        // and commit cleanly inside the V1 Chronicle capsule ceiling.
        let fit_entries: Vec<fa_intents::PostIntent> = (0..fit_count)
            .map(|i| {
                make_entry_intent(
                    &book,
                    usd,
                    cash,
                    rent,
                    &evidence,
                    120,
                    format!("fit-{i:03}").as_bytes(),
                )
            })
            .collect();
        let fit_batch = PostBatch::new(b"fit-capsule-batch".to_vec(), fit_entries).expect("batch");
        let posted = runtime
            .block_on(post_batch(&mut db, &ctx, &book, cap, fit_batch))
            .expect("kernel")
            .expect("fit_count-entry batch within MAX_BATCH_TEMPLATE_BYTES must commit");
        assert_eq!(posted.entries.len(), fit_count);
        assert!(!posted.already_recorded);
    }
}
