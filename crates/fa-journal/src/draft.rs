//! Drafts (plan §15.2, Appendix A `DraftSet`, Appendix H R-BR interim
//! posture; bead fa-s7x).
//!
//! A draft is an intent log. Its history is exactly its `DraftControl`
//! records (class 25, control kind 11), each a `LifecycleTransition` on the
//! `DraftSet` vertex at [`fa_model::draft_vid`]:
//!
//! - **Open** (`0 → Open`) journals the draft's immutable body (extension 8
//!   `fa:draft-body:v1`: its book, name and owner) and creates the vertex with
//!   `state = Open`.
//! - **Plan** (`Open → Open`) journals one intent (extension 9
//!   `fa:draft-intent:v3`: the `PostIntent`'s canonical bytes, the planner's
//!   capability, and the resolved Entry with its digest). The entire ordered draft is
//!   rehearsed through the real batch pipeline first; each intent sees its
//!   predecessors' effects. Previously reviewed effects must still match.
//!   Its identity derives from the draft and the
//!   intent's key, so a retry is its recorded outcome.
//!   A v4 Plan record atomically appends a complete ordered PostBatch, retaining
//!   each member's v3 reviewed entry. The batch key uses a distinct record
//!   namespace; membership and order are part of its retry comparison.
//!   A v5 Plan record retains one complete Reversal/Replacement correction
//!   in a dedicated draft. Its members share one record and are never
//!   independently publishable or mixed with ordinary draft members.
//! - **Promote** (`Open → Promoted`) replays the planned intents to trunk in
//!   one `PostBatch`, or through the native correction-pair protocol, in the same transaction as the
//!   record (FA-INV-09). The promoter holds `approve` (the `draft-promote`
//!   row; no Agent- or System-profile capability can) and is never the
//!   draft's owner. Each intent posts under its planner's own capability,
//!   every admission check of which runs again against current trunk —
//!   period law, ceilings, scope, revocation, evidence — except the Agent's
//!   trunk denial, which the promoter's authority answers
//!   ([`crate::post::Admission::Promote`]). The promoted entries keep the
//!   planner as their principal and point at the draft by `IN_CASE`. Their
//!   exact Entry digests must match the reviewed effects retained at Plan.
//! - **Discard** (`Open → Discarded`) closes the draft; nothing is deleted.
//!
//! Every record moves or witnesses `state` in its own transaction, so a
//! Promote and a Discard (or a Plan) racing on one draft are a
//! first-committer-wins conflict. Nothing in a draft is a trunk entry until
//! its promotion commits.

use fa_intents::{PostBatch, PostIntent};
use fa_model::symbols::{label, property, relation};
use fa_model::{
    ControlKind, ControlPayload, Entry, EntryClass, EntryOrigin, EntryPayload, EntryRef, Erasable,
    Id128, Reader, TypedRef, Writer, domain_digest, draft_vid, entry_mirrors, entry_vid,
};
use fa_policy::{Capability, Denial, Intent, Op};
use fa_time::DateDay;
use fgdb::{Database, VertexRow, WriteBatch, WriteMismatchPolicy, WriteTxn, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, QueryCx, VId};

use crate::batch::{BatchStage, commit_batch, read_outcome, stage_batch};
use crate::genesis::BookContext;
use crate::policy::{capability_witness, refusal as denial, steward};
use crate::post::Admission;
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{bytes, edge_id, prop, scalar_bytes, scalar_text};

mod batch;
mod correction;
mod rehearsal;
use batch::decode_plan_record;
pub use batch::plan_batch_into_draft;
pub use correction::plan_correction_into_draft;
pub(crate) use rehearsal::Rehearsing;
pub use rehearsal::{
    DraftRehearsal, DraftRehearsalRequest, DraftRehearsalSource, DraftSourceRecord,
    rehearse_draft_into,
};

/// Canonical bytes of a draft body: `u16 version ‖ book_id[16] ‖ str name ‖
/// u128 owner_principal` (extension 8).
pub const DRAFT_BODY_VERSION: u16 = 1;
/// Canonical bytes of a planned intent: `u16 version ‖ bytes post_intent ‖
/// bytes capability ‖ resolved_entry_digest[32] ‖ bytes resolved_entry`
/// (extension 9). Empty resolved bytes losslessly denote the Entry sealed
/// from the already retained exact proposal and approvals, with no plan
/// certificate. Version 1 omits both resolved fields; version 2 retains only
/// the digest. Historical versions remain readable with their original bytes.
pub const DRAFT_INTENT_VERSION: u16 = 3;
/// A draft name's bound, in bytes.
pub const MAX_DRAFT_NAME_BYTES: usize = 128;
const DRAFT_BODY_DOMAIN: &[u8] = b"fa:draft-body:v1";
const RECORD_KEY_DOMAIN: &[u8] = b"fa:draft-record-key:v1";
const PROMOTION_KEY_DOMAIN: &[u8] = b"fa:draft-promotion-key:v1";

/// The token [`Admission::Promote`] carries. Only this module makes one,
/// after admitting the promoter and before staging the promotion, so no
/// other path can waive the Agent's trunk denial.
#[derive(Clone, Copy, Debug)]
pub struct Promoting(());

/// Only a draft's admitted preview can revalidate retained aggregate sources
/// across its own journaled planning records. This remains a zero-write plan,
/// and does not grant either promotion or direct trunk authority.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Planning(());

/// The `state` projection of a `DraftSet` (lifecycle-by-transition).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DraftState {
    Open,
    Promoted,
    Discarded,
}

impl DraftState {
    /// The `LifecycleTransition` state tag; 0 is "no draft yet".
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            Self::Open => 1,
            Self::Promoted => 2,
            Self::Discarded => 3,
        }
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Promoted => "promoted",
            Self::Discarded => "discarded",
        }
    }

    fn scalar(self) -> CanonicalScalar {
        CanonicalScalar::Int(i64::from(self.tag()))
    }

    fn from_scalar(v: Option<&CanonicalScalar>) -> Option<Self> {
        match v {
            Some(CanonicalScalar::Int(1)) => Some(Self::Open),
            Some(CanonicalScalar::Int(2)) => Some(Self::Promoted),
            Some(CanonicalScalar::Int(3)) => Some(Self::Discarded),
            _ => None,
        }
    }
}

/// A draft's immutable body (Appendix A `DraftSet`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DraftBody {
    pub book_id: Id128,
    pub name: String,
    pub owner: VId,
}

impl DraftBody {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, KernelError> {
        let mut w = Writer::with_capacity(48 + self.name.len());
        w.u16(DRAFT_BODY_VERSION)
            .fixed(&self.book_id.0)
            .str(&self.name)
            .u128(self.owner.0);
        Ok(w.finish()?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, KernelError> {
        let mut r = Reader::new(bytes);
        if r.u16("draft.version").map_err(decode)? != DRAFT_BODY_VERSION {
            return Err(KernelError::Corrupt(
                "unsupported draft body version".into(),
            ));
        }
        let book_id = Id128(r.fixed("draft.book_id").map_err(decode)?);
        let name = r
            .str(MAX_DRAFT_NAME_BYTES, "draft.name")
            .map_err(decode)?
            .to_string();
        let owner = VId(r.u128("draft.owner").map_err(decode)?);
        r.finish().map_err(decode)?;
        Ok(Self {
            book_id,
            name,
            owner,
        })
    }

    pub fn digest(&self) -> Result<[u8; 32], KernelError> {
        Ok(domain_digest(
            DRAFT_BODY_DOMAIN,
            &[&self.canonical_bytes()?],
        ))
    }

    #[must_use]
    pub fn vid(&self) -> VId {
        draft_vid(self.book_id, &self.name)
    }
}

/// One planned intent as its Plan record journals it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannedIntent {
    /// The Plan record.
    pub record: VId,
    pub recorded_at: CommitSeq,
    pub intent: PostIntent,
    /// The planner's capability, under which the promotion replays it.
    pub capability: Capability,
    /// The exact Entry rehearsed when this intent entered its ordered draft.
    /// Historical v1 draft records and scenario records have no such binding.
    pub resolved_entry_digest: Option<[u8; 32]>,
    /// Exact reviewed Entry retained by v3 for dependencies after discard or
    /// availability drift; never authority to bypass new append validation.
    pub resolved_entry: Option<Entry>,
}

fn intent_bytes(
    intent: &PostIntent,
    capability: &Capability,
    resolved_entry_digest: Option<[u8; 32]>,
    resolved_entry: Option<&Entry>,
) -> Result<Vec<u8>, KernelError> {
    if let Some(entry) = resolved_entry {
        check_retained_entry(intent, resolved_entry_digest, entry)?;
    }
    let resolved_bytes = resolved_entry
        .map(|entry| {
            let original = intent
                .proposal()
                .clone()
                .seal(intent.approvals().to_vec(), None)?;
            if *entry == original {
                Ok(Vec::new())
            } else {
                entry.encode()
            }
        })
        .transpose()?;
    let intent = intent.canonical_bytes().map_err(intent_error)?;
    let capability = capability
        .canonical_bytes()
        .map_err(|e| KernelError::Corrupt(format!("capability bytes: {e}")))?;
    let mut w = Writer::with_capacity(8 + intent.len() + capability.len());
    w.u16(if resolved_entry.is_some() {
        DRAFT_INTENT_VERSION
    } else if resolved_entry_digest.is_some() {
        2
    } else {
        1
    })
    .bytes(&intent)
    .bytes(&capability);
    if let Some(digest) = resolved_entry_digest {
        w.fixed(&digest);
    }
    if let Some(bytes) = resolved_bytes {
        w.bytes(&bytes);
    }
    Ok(w.finish()?)
}

type DecodedIntent = (PostIntent, Capability, Option<[u8; 32]>, Option<Entry>);

fn check_retained_entry(
    intent: &PostIntent,
    digest: Option<[u8; 32]>,
    entry: &Entry,
) -> Result<(), KernelError> {
    let request =
        crate::limit::request_form(&entry.proposal)?.unwrap_or_else(|| entry.proposal.clone());
    let original =
        crate::limit::request_form(intent.proposal())?.unwrap_or_else(|| intent.proposal().clone());
    if digest != Some(entry.entry_digest)
        || entry.approvals != intent.approvals()
        || entry.plan_certificate.is_some()
        || request != original
    {
        return Err(KernelError::Corrupt(
            "draft retained Entry does not bind its original request, approvals and reviewed digest"
                .into(),
        ));
    }
    Ok(())
}

fn decode_intent(bytes: &[u8]) -> Result<DecodedIntent, KernelError> {
    let mut r = Reader::new(bytes);
    let version = r.u16("draft_intent.version").map_err(decode)?;
    if !(1..=DRAFT_INTENT_VERSION).contains(&version) {
        return Err(KernelError::Corrupt(
            "unsupported draft intent version".into(),
        ));
    }
    let intent = PostIntent::decode(
        r.bytes(fa_model::limits::MAX_ENTRY_BYTES, "draft_intent.intent")
            .map_err(decode)?,
    )
    .map_err(intent_error)?;
    let capability = Capability::decode(
        r.bytes(64 * 1024, "draft_intent.capability")
            .map_err(decode)?,
    )
    .map_err(|e| KernelError::Corrupt(format!("draft intent capability: {e}")))?;
    let resolved_entry_digest = if version >= 2 {
        Some(
            r.fixed("draft_intent.resolved_entry_digest")
                .map_err(decode)?,
        )
    } else {
        None
    };
    let resolved_entry = if version == DRAFT_INTENT_VERSION {
        let bytes = r
            .bytes(
                fa_model::limits::MAX_ENTRY_BYTES,
                "draft_intent.resolved_entry",
            )
            .map_err(decode)?;
        let original = intent
            .proposal()
            .clone()
            .seal(intent.approvals().to_vec(), None)?;
        let entry = if bytes.is_empty() {
            original
        } else {
            let entry = Entry::decode(bytes)?;
            if entry == original {
                return Err(KernelError::Corrupt(
                    "draft retained Entry repeats the original instead of its canonical empty encoding"
                        .into(),
                ));
            }
            entry
        };
        check_retained_entry(&intent, resolved_entry_digest, &entry)?;
        Some(entry)
    } else {
        None
    };
    r.finish().map_err(decode)?;
    Ok((intent, capability, resolved_entry_digest, resolved_entry))
}

fn decode(e: fa_model::DecodeError) -> KernelError {
    KernelError::Model(e.into())
}

fn intent_error(e: fa_intents::IntentError) -> KernelError {
    KernelError::Corrupt(format!("draft intent: {e}"))
}

/// A draft as its records state it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DraftView {
    pub vid: VId,
    pub body: DraftBody,
    pub state: DraftState,
    pub opened_at: CommitSeq,
    /// In planning order: the promotion's member order.
    pub intents: Vec<PlannedIntent>,
    /// The Promote or Discard record, and the principal who made it.
    pub closed: Option<DraftClosure>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DraftClosure {
    pub record: VId,
    pub recorded_at: CommitSeq,
    pub by: VId,
    /// A promotion's IntentOutcome and its entries, in member order.
    pub promoted: Option<(VId, Vec<EntryRef>)>,
}

/// A draft control request: the acting capability, the record's (undated,
/// book-scoped) effective date and its sealed description.
#[derive(Clone, Debug)]
pub struct DraftRequest {
    pub capability: Capability,
    pub effective_date: DateDay,
    pub description: Erasable<String>,
}

/// One recorded draft control (Open, Plan or Discard).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DraftRecorded {
    pub draft: VId,
    pub control_entry: VId,
    pub recorded_at: CommitSeq,
    /// The same record was already journaled (FA-INV-09): nothing written.
    pub already_recorded: bool,
}

/// One member's original request and exact resolved effects in an ordered
/// draft rehearsal. It carries no authority to publish a trunk entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DraftPreviewMember {
    pub intent: PostIntent,
    pub capability_commitment: [u8; 32],
    pub entry: Entry,
    pub period: String,
}

/// A zero-write rehearsal of the complete draft in planning order, optionally
/// including a candidate being appended. This is not a portable single-entry PostPlan:
/// later members may depend on earlier members' staged effects. Promotion
/// revalidates the retained per-member Entry digests in one transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DraftPreview {
    draft: VId,
    principal: VId,
    snapshot_seq: CommitSeq,
    members: Vec<DraftPreviewMember>,
    effects_digest: [u8; 32],
}

impl DraftPreview {
    #[must_use]
    pub fn draft(&self) -> VId {
        self.draft
    }

    #[must_use]
    pub fn principal(&self) -> VId {
        self.principal
    }

    #[must_use]
    pub fn snapshot_seq(&self) -> CommitSeq {
        self.snapshot_seq
    }

    #[must_use]
    pub fn members(&self) -> &[DraftPreviewMember] {
        &self.members
    }

    #[must_use]
    pub fn effects_digest(&self) -> [u8; 32] {
        self.effects_digest
    }

    pub fn digest(&self) -> Result<[u8; 32], KernelError> {
        let mut w = Writer::new();
        w.u128(self.draft.0)
            .u128(self.principal.0)
            .u64(self.snapshot_seq.0)
            .fixed(&self.effects_digest);
        let bindings = self
            .members
            .iter()
            .map(|member| {
                Ok((
                    member.intent.digest().map_err(intent_error)?,
                    member.capability_commitment,
                    member.entry.entry_digest,
                    member.period.as_str(),
                ))
            })
            .collect::<Result<Vec<_>, KernelError>>()?;
        w.list(&bindings, |w, (request, capability, entry, period)| {
            w.fixed(request).fixed(capability).fixed(entry).str(period);
        });
        Ok(domain_digest(b"fa:draft-preview:v1", &[&w.finish()?]))
    }
}

/// A recorded Plan: the record, and the rehearsal it passed (absent on a
/// recorded retry, which rehearses nothing).
#[derive(Clone, Debug)]
pub struct DraftPlanned {
    pub recorded: DraftRecorded,
    pub plan: Option<DraftPreview>,
}

/// A recorded promotion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DraftPromoted {
    pub draft: VId,
    pub control_entry: VId,
    pub outcome: VId,
    /// The promoted entries, in member order.
    pub entries: Vec<EntryRef>,
    /// Each entry's resolved period; empty for a recorded promotion.
    pub periods: Vec<String>,
    pub recorded_at: CommitSeq,
    pub already_recorded: bool,
}

#[derive(Clone, Copy)]
enum Kind {
    Open,
    Plan,
    PlanBatch,
    PlanCorrection,
    Promote,
    Discard,
}

impl Kind {
    fn transition(self) -> &'static str {
        match self {
            Self::Open => "Open",
            Self::Plan | Self::PlanBatch | Self::PlanCorrection => "Plan",
            Self::Promote => "Promote",
            Self::Discard => "Discard",
        }
    }

    fn tag(self) -> u8 {
        match self {
            Self::Open => 0,
            Self::Plan => 1,
            Self::Promote => 2,
            Self::Discard => 3,
            Self::PlanBatch => 4,
            Self::PlanCorrection => 5,
        }
    }

    fn states(self) -> (u8, DraftState) {
        match self {
            Self::Open => (0, DraftState::Open),
            Self::Plan | Self::PlanBatch | Self::PlanCorrection => {
                (DraftState::Open.tag(), DraftState::Open)
            }
            Self::Promote => (DraftState::Open.tag(), DraftState::Promoted),
            Self::Discard => (DraftState::Open.tag(), DraftState::Discarded),
        }
    }
}

/// A record's idempotency key: `H(domain ‖ kind ‖ draft ‖ discriminator)`,
/// within the key bound whatever the intent's own key.
fn record_key(kind: Kind, draft: VId, discriminator: &[u8]) -> Vec<u8> {
    domain_digest(
        RECORD_KEY_DOMAIN,
        &[&[kind.tag()], &draft.0.to_le_bytes(), discriminator],
    )
    .to_vec()
}

fn record_vid(book: &BookContext, proposal: &EntryPayload) -> VId {
    entry_vid(
        book.book_id,
        &proposal.principal_ref.0.to_le_bytes(),
        &proposal.idempotency_key,
    )
}

#[allow(clippy::too_many_arguments)]
fn record_proposal(
    book: &BookContext,
    body: &DraftBody,
    kind: Kind,
    principal: VId,
    discriminator: &[u8],
    req: &DraftRequest,
    proof_refs: Vec<TypedRef>,
    extensions: Vec<(u16, Vec<u8>)>,
) -> Result<EntryPayload, KernelError> {
    let draft = body.vid();
    let (from, to) = kind.states();
    Ok(EntryPayload {
        schema_minor: fa_model::entry::EXTENSIONS_MINOR,
        book_id: book.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::DRAFT_CONTROL,
        effective_date: req.effective_date,
        document_date: None,
        description: req.description.clone(),
        effective_period: None,
        legs: Vec::new(),
        control: Some(ControlPayload::LifecycleTransition {
            object_ref: draft,
            from,
            to: to.tag(),
            proof_refs,
            reason_code: 0,
        }),
        unit_totals: Vec::new(),
        base_totals: None,
        idempotency_key: record_key(kind, draft, discriminator),
        origin: EntryOrigin::Control {
            control_kind: ControlKind::DRAFT_TRANSITION,
            spec_body_digest: body.digest()?,
        },
        principal_ref: principal,
        session_ref: None,
        evidence: Vec::new(),
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions,
        tags: Vec::new(),
    })
}

/// Authority before any read (doctrine 8): the `DraftControl` row's preparer
/// op for `kind`, held by the acting principal, current at the head. A
/// draft record is not a trunk entry, so an Agent may open, plan into and
/// discard its draft (plan §14.4).
fn admit<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    capability: &Capability,
    kind: Kind,
) -> Outcome<()> {
    let op = steward()?
        .transition_op("DraftControl", kind.transition())
        .ok_or_else(|| {
            KernelError::Corrupt(format!(
                "sod_policy.toml registers no DraftControl {} rule; the record is refused, never unconstrained",
                kind.transition()
            ))
        })?;
    if let Err(d) = fa_policy::admit(
        capability,
        &Intent {
            principal: capability.holder(),
            trunk: false,
            op,
            book: book.book_id,
            legs: &[],
        },
    ) {
        return Ok(Err(denial(&d)));
    }
    // Every lifecycle path, including a retained retry that returns before
    // opening a transaction, needs current issuance and revocation admission
    // before it observes the draft. Writers still witness authority in txn.
    crate::policy::current_at(db, book, capability).map(|result| result.map(|_| ()))
}

fn usage(message: impl Into<String>, fix: &str) -> Refusal {
    Refusal::new(
        code::STRUCTURE,
        exit::USAGE,
        message.into(),
        "plan §15.2, Appendix A DraftSet (bead fa-s7x)",
        fix,
    )
}

fn unknown(name: &str) -> Refusal {
    Refusal::new(
        code::DRAFT_UNKNOWN,
        exit::REFUSAL,
        format!("this book has no draft named `{name}`"),
        "plan §15.2 (drafts; bead fa-s7x)",
        format!(
            "list the book's drafts with `fa draft list --json`, or open this one with `fa draft new {}`",
            crate::refusal::command_word(name)
        ),
    )
    .at("draft", name)
}

/// The first `<name>-<n>` (n in 2..=64) that names no draft yet, within the
/// name bound: the fresh draft a closed draft's fix plans into.
fn fresh_name<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    name: &str,
) -> Result<Option<String>, KernelError> {
    for n in 2..=64u32 {
        let candidate = format!("{name}-{n}");
        if candidate.len() > MAX_DRAFT_NAME_BYTES {
            return Ok(None);
        }
        if db.vertex(draft_vid(book.book_id, &candidate))?.is_none() {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

fn not_open(body: &DraftBody, state: DraftState) -> Refusal {
    Refusal::new(
        code::DRAFT_NOT_OPEN,
        exit::REFUSAL,
        format!(
            "draft `{}` is {}: it takes no further records",
            body.name,
            state.name()
        ),
        "plan §15.2 (a promoted or discarded draft is closed; its history is immutable)",
        "open a new draft with `fa draft new <name>` and plan the intents into it",
    )
}

fn check_name(name: &str) -> Result<(), Refusal> {
    if name.is_empty()
        || name.len() > MAX_DRAFT_NAME_BYTES
        || name.trim() != name
        || name.chars().any(char::is_control)
    {
        return Err(usage(
            "a draft name is 1..=128 bytes with no surrounding whitespace or control characters",
            "fa draft new <name>   (for example close-2026-03)",
        ));
    }
    Ok(())
}

fn conflict_with(row: &VertexRow) -> Refusal {
    Refusal::new(
        code::IDEMPOTENCY_CONFLICT,
        exit::CONFLICT,
        format!(
            "this draft record's identity holds different content; the recorded entry is {:032x}",
            row.vid.0
        ),
        "plan §4.9 (identity is derived; content is bound by proposal_digest)",
        "resubmit the identical record to get its recorded outcome, or use a new name or intent key",
    )
}

/// The identical record's outcome, or the conflict (plan §4.9: exact bytes,
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
                    "the recorded draft record {:032x} has erased text, so a retry cannot be judged identical",
                    row.vid.0
                ),
                "plan §4.9, §14.6 (erasure leaves identity, not plaintext)",
                "use a new name or intent key",
            )))
        }
        (Err(e), _) | (_, Err(e)) => Err(e.into()),
    }
}

fn draft_row_body(row: &VertexRow) -> Result<DraftBody, KernelError> {
    DraftBody::decode(&bytes(row, property::FA_PAYLOAD, "draft._fa_payload")?)
}

/// Witness the draft inside `txn` (a property-granular point read of its
/// state): a Promote or Discard that commits first makes this transaction a
/// first-committer-wins conflict.
fn witness_open<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    book: &BookContext,
    name: &str,
) -> Outcome<DraftBody> {
    let vid = draft_vid(book.book_id, name);
    let Some(row) = txn.vertex(db, vid)? else {
        return Ok(Err(unknown(name)));
    };
    if !row.labels.contains(&label::DRAFT_SET) {
        return Err(KernelError::Corrupt(format!(
            "draft identity {:032x} holds a vertex that is not a DraftSet",
            vid.0
        )));
    }
    let body = draft_row_body(&row)?;
    let state = DraftState::from_scalar(txn.vertex_property(db, vid, property::STATE)?.as_ref())
        .ok_or_else(|| KernelError::Corrupt(format!("draft {:032x} state mirror", vid.0)))?;
    if state != DraftState::Open {
        return Ok(Err(not_open(&body, state)));
    }
    Ok(Ok(body))
}

/// Open state alone does not change when another Plan is appended. Bind the
/// complete reviewed intent set to the native adjacency witness as well, so
/// concurrent planning cannot mix operations or add an unreviewed member to
/// a promotion. The Open record and every atomic Plan record are its members.
fn witness_membership<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    book: &BookContext,
    view: &DraftView,
) -> Outcome<()> {
    let open = entry_vid(
        book.book_id,
        &view.body.owner.0.to_le_bytes(),
        &record_key(Kind::Open, view.vid, &[]),
    );
    let expected: std::collections::BTreeSet<_> = std::iter::once(open)
        .chain(view.intents.iter().map(|member| member.record))
        .collect();
    let actual: std::collections::BTreeSet<_> = txn
        .in_neighbours(db, view.vid, relation::IN_CASE)?
        .into_iter()
        .collect();
    if actual != expected {
        return Ok(Err(fcw(
            "the draft's planned membership changed",
            "draft operation",
        )));
    }
    Ok(Ok(()))
}

fn fcw(detail: &str, what: &str) -> Refusal {
    Refusal::new(
        code::CONFLICT,
        exit::CONFLICT,
        format!("a concurrent commit invalidated a witness this {what} read: {detail}"),
        "FG-LAW-FCW-01 (first committer wins)",
        "retry; if the draft was promoted or discarded meanwhile, the retry says so",
    )
}

/// Commit a draft record's transaction, mapping the substrate's outcomes.
async fn finish<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    mut txn: WriteTxn,
    proposal: &EntryPayload,
    draft: VId,
    control_entry: VId,
) -> Outcome<DraftRecorded> {
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(DraftRecorded {
            draft,
            control_entry,
            recorded_at: seq,
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(fcw(&detail, "draft record")))
        }
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => match db.vertex(control_entry)? {
            Some(row) => Ok(
                recorded_or_conflict(book, &row, proposal)?.map(|recorded_at| DraftRecorded {
                    draft,
                    control_entry,
                    recorded_at,
                    already_recorded: true,
                }),
            ),
            None => Err(KernelError::Corrupt(
                "draft record identity spent but no live row".into(),
            )),
        },
        Err(e) => Err(e.into()),
    }
}

/// Open the draft `name` owned by the capability's holder: one commit
/// journaling the Open record, the `DraftSet` vertex with its immutable body
/// and `state = Open`, and the record's `IN_CASE` edge to it.
pub async fn open_draft<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    name: &str,
    req: DraftRequest,
) -> Outcome<DraftRecorded> {
    if let Err(r) = check_name(name) {
        return Ok(Err(r));
    }
    if let Err(r) = admit(db, book, &req.capability, Kind::Open)? {
        return Ok(Err(r));
    }
    let body = DraftBody {
        book_id: book.book_id,
        name: name.to_string(),
        owner: req.capability.holder(),
    };
    let body_bytes = body.canonical_bytes()?;
    let proposal = record_proposal(
        book,
        &body,
        Kind::Open,
        body.owner,
        &[],
        &req,
        Vec::new(),
        vec![(fa_model::entry::DRAFT_BODY_EXTENSION, body_bytes.clone())],
    )?;
    if proposal.validate().is_err() {
        return Ok(Err(usage(
            "the Open record is not a valid DraftControl entry",
            "open the draft with `fa draft new <name>`",
        )));
    }
    let draft = body.vid();
    let evid = record_vid(book, &proposal);
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
            recorded_or_conflict(book, &row, &proposal)?.map(|recorded_at| DraftRecorded {
                draft,
                control_entry: evid,
                recorded_at,
                already_recorded: true,
            }),
        );
    }
    if let Some(existing) = txn.vertex(db, draft)? {
        txn.abort();
        let owner = draft_row_body(&existing).map(|b| b.owner).ok();
        return Ok(Err(Refusal::new(
            code::IDEMPOTENCY_CONFLICT,
            exit::CONFLICT,
            // The row's created_at starts its current version, not the
            // draft's opening, so only the owner is named here.
            format!(
                "draft `{name}` already exists{}",
                owner.map_or_else(String::new, |o| format!(
                    " (opened by principal {:032x})",
                    o.0
                ))
            ),
            "plan §15.2 (one draft per name in a book)",
            "choose another name, or inspect it with `fa draft show <name> --json`",
        )));
    }
    let entry = proposal.clone().seal(Vec::new(), None)?;
    let mut props = vec![
        (
            property::FA_PAYLOAD,
            scalar_bytes("draft._fa_payload", body_bytes)?,
        ),
        (
            property::FA_DIGEST,
            scalar_bytes("draft._fa_digest", body.digest()?.to_vec())?,
        ),
        (
            property::BOOK_ID,
            scalar_bytes("book_id", book.book_id.0.to_vec())?,
        ),
        (property::CODE, scalar_text("draft.code", name)?),
        (property::STATE, DraftState::Open.scalar()),
    ];
    props.sort_by_key(|(k, _)| k.0);
    let mut in_case = WriteBatch::new(relation::IN_CASE);
    in_case.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    in_case.create_vertex(draft, vec![label::DRAFT_SET], props);
    in_case.add_edge(edge_id(relation::IN_CASE, evid, draft), evid, draft, vec![]);
    txn.write(db, in_case)?;
    finish(db, ctx, book, txn, &proposal, draft, evid).await
}

fn changed_effects(name: &str, index: usize, reason: &str) -> Refusal {
    Refusal::new(
        code::PLAN_INVALIDATED,
        exit::CONFLICT,
        format!("draft `{name}` member {index}: {reason}; nothing was recorded"),
        "plan §15.2 (promotion preserves the ordered draft's reviewed effects)",
        "review current availability and open a new draft with the intended effects",
    )
    .at("member", index)
}

fn check_resolved_members(
    name: &str,
    planned: &[PlannedIntent],
    resolved: &[EntryRef],
) -> Result<(), Refusal> {
    if planned.len() != resolved.len() {
        return Err(changed_effects(name, 0, "the reviewed membership changed"));
    }
    for (index, (planned, resolved)) in planned.iter().zip(resolved).enumerate() {
        match planned.resolved_entry_digest {
            Some(digest) if digest != resolved.entry_digest => {
                return Err(changed_effects(
                    name,
                    index,
                    "the resolved entry differs from its reviewed effects",
                ));
            }
            None if planned
                .intent
                .proposal()
                .extensions
                .iter()
                .any(|(tag, _)| *tag == fa_model::entry::BALANCING_EXTENSION) =>
            {
                return Err(changed_effects(
                    name,
                    index,
                    "a historical balancing request has no retained reviewed effects",
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

async fn preview_ordered<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    view: &DraftView,
    candidates: &[(PostIntent, &Capability)],
) -> Outcome<DraftPreview> {
    if correction::is_correction(view) {
        if !candidates.is_empty() {
            return Ok(Err(correction::dedicated()));
        }
        return correction::preview(db, ctx, book, view).await;
    }
    let mut members: Vec<_> = view.intents.iter().map(|i| i.intent.clone()).collect();
    let mut capabilities: Vec<_> = view.intents.iter().map(|i| i.capability.clone()).collect();
    for (intent, capability) in candidates {
        members.push(intent.clone());
        capabilities.push((*capability).clone());
    }
    let batch = match PostBatch::new(promotion_key(view.vid), members) {
        Ok(batch) => batch,
        Err(error) => {
            return Ok(Err(usage(
                format!(
                    "draft `{}` does not form one batch: {error}",
                    view.body.name
                ),
                "plan compatible intents into one draft in execution order",
            )));
        }
    };
    // Every retained planner is admitted before loading native history; a
    // caller's authority cannot replace a previous member's capability.
    for (intent, capability) in batch.members().iter().zip(&capabilities) {
        if let Err(d) = fa_policy::reach(capability, &fa_policy::Reach::whole_book(true), None) {
            return Ok(Err(denial(&d)));
        }
        let request = crate::post::PostRequest {
            proposal: intent.proposal().clone(),
            approvals: intent.approvals().to_vec(),
            capability: capability.clone(),
            plan_certificate: None,
        };
        if let Err(refusal) = crate::post::authorize_request(db, book, &request, Admission::Plan)? {
            return Ok(Err(refusal));
        }
    }
    if let Err(refusal) = crate::scratch::ensure_history(db, ctx).await? {
        return Ok(Err(refusal));
    }
    let staged = match stage_batch(
        db,
        ctx,
        book,
        &capabilities,
        &batch,
        Admission::PlanDraft(Planning(())),
    )? {
        Err(refusal) => return Ok(Err(refusal)),
        Ok(BatchStage::Recorded(_)) => {
            return Err(KernelError::Corrupt(format!(
                "draft `{}` is open but its promotion batch is already recorded",
                view.body.name
            )));
        }
        Ok(BatchStage::Staged(staged)) => staged,
    };
    if let Err(refusal) = check_resolved_members(
        &view.body.name,
        &view.intents,
        &staged.entries[..view.intents.len()],
    ) {
        staged.txn.abort();
        return Ok(Err(refusal));
    }
    let mut members = Vec::with_capacity(batch.members().len());
    for (((intent, capability), entry), period) in batch
        .members()
        .iter()
        .zip(&capabilities)
        .zip(staged.prepared_entries())
        .zip(&staged.periods)
    {
        members.push(DraftPreviewMember {
            intent: intent.clone(),
            capability_commitment: capability
                .commitment()
                .map_err(|e| KernelError::Corrupt(format!("draft capability: {e}")))?,
            entry: entry.clone(),
            period: period.clone(),
        });
    }
    let preview = DraftPreview {
        draft: view.vid,
        principal: view.body.owner,
        snapshot_seq: staged.txn.basis(),
        members,
        effects_digest: staged.txn.staged_effect_digest()?.0,
    };
    staged.txn.abort();
    Ok(Ok(preview))
}

/// Current planning authority and ownership precede member-history access.
fn owned_draft<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    name: &str,
) -> Outcome<DraftView> {
    if let Err(refusal) = check_name(name) {
        return Ok(Err(refusal));
    }
    if let Err(d) = fa_policy::reach(capability, &fa_policy::Reach::whole_book(true), None) {
        return Ok(Err(denial(&d)));
    }
    if let Err(refusal) = admit(db, book, capability, Kind::Plan)? {
        return Ok(Err(refusal));
    }
    let vid = draft_vid(book.book_id, name);
    let Some(row) = db.vertex(vid)? else {
        return Ok(Err(unknown(name)));
    };
    if !row.labels.contains(&label::DRAFT_SET) {
        return Err(KernelError::Corrupt(format!(
            "draft identity {:032x} holds a vertex that is not a DraftSet",
            vid.0
        )));
    }
    let body = draft_row_body(&row)?;
    if body.owner != capability.holder() {
        return Ok(Err(Refusal::new(
            code::CAPABILITY,
            exit::SAFETY,
            format!("only the owner may prepare further intents for draft `{name}`"),
            "plan §15.2 (a draft is its owner's intent log)",
            "open your own draft with `fa draft new <name>`",
        )));
    }
    Ok(Ok(view_of(db, &ctx.query(), &row)?))
}

/// Rehearse the retained members of the owner's open draft without appending
/// a Plan record or publishing any entry. Every member runs under its own
/// original capability and must retain its reviewed Entry digest. An empty
/// open draft returns `None`; a closed or drifted draft refuses. To construct
/// dependent retries from original reviewed targets, use [`draft_entries`].
pub async fn preview_draft<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    name: &str,
) -> Outcome<Option<DraftPreview>> {
    let view = match owned_draft(db, ctx, book, capability, name)? {
        Ok(view) => view,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if view.state != DraftState::Open {
        return Ok(Err(not_open(&view.body, view.state)));
    }
    if view.intents.is_empty() {
        return Ok(Ok(None));
    }
    Ok(preview_ordered(db, ctx, book, &view, &[]).await?.map(Some))
}

/// Original resolved entries retained with the owner's planned requests.
/// Reading them does not rehearse against current availability or reopen a
/// closed draft. They let a dependent request reconstruct the same target on
/// an exact retry; `plan_into_draft` still decides recorded retry versus new
/// append, and revalidates every new append through the ordered pipeline.
///
/// Historical v1/v2 drafts have no complete retained Entry. For those, an
/// open draft must pass the current ordered preview before its targets can be
/// returned. A digest alone is never presented as a reconstructed entry.
pub async fn draft_entries<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    name: &str,
) -> Outcome<Vec<Entry>> {
    let view = match owned_draft(db, ctx, book, capability, name)? {
        Ok(view) => view,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if let Some(entries) = view
        .intents
        .iter()
        .map(|planned| planned.resolved_entry.clone())
        .collect::<Option<Vec<_>>>()
    {
        return Ok(Ok(entries));
    }
    if view.state != DraftState::Open {
        return Ok(Err(not_open(&view.body, view.state)));
    }
    Ok(preview_ordered(db, ctx, book, &view, &[])
        .await?
        .map(|preview| {
            preview
                .members
                .into_iter()
                .map(|member| member.entry)
                .collect()
        }))
}

/// Plan `intent` into the open draft `name` (plan §15.2 `plan_in_draft`):
/// rehearse the whole ordered draft through the real batch pipeline, then journal one
/// Plan record. Only the draft's owner plans into it; the intent is the
/// owner's, on trunk, under a key no other intent in the draft holds.
pub async fn plan_into_draft<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    name: &str,
    intent: PostIntent,
    req: DraftRequest,
) -> Outcome<DraftPlanned> {
    if let Err(r) = check_name(name) {
        return Ok(Err(r));
    }
    if let Err(r) = admit(db, book, &req.capability, Kind::Plan)? {
        return Ok(Err(r));
    }
    let p = intent.proposal();
    if p.principal_ref != req.capability.holder() {
        return Ok(Err(denial(&Denial::NotHolder {
            holder: req.capability.holder(),
            principal: p.principal_ref,
        })));
    }
    if p.book_id != book.book_id || p.branch_id != Id128::TRUNK {
        return Ok(Err(usage(
            "a draft plans intents for this book's trunk",
            "plan the intent with this book's id and the trunk branch",
        )));
    }
    // Its promotion is one batch, so only a batchable class is planned.
    if !crate::batch::batchable(p.class) {
        return Ok(Err(usage(
            format!(
                "a {} entry cannot join a draft: its promotion is one batch of PostEntry intents",
                p.class.name().unwrap_or("?")
            ),
            "plan Original, Adjusting, Reversal, Pending or Resolution entries; post allocations and migration chunks through their own verbs",
        )));
    }
    let Some(view) = read_draft(db, &ctx.query(), book, name)? else {
        return Ok(Err(unknown(name)));
    };
    if view.body.owner != req.capability.holder() {
        return Ok(Err(Refusal::new(
            code::CAPABILITY,
            exit::SAFETY,
            format!(
                "draft `{name}` belongs to principal {:032x}; only its owner plans into it",
                view.body.owner.0
            ),
            "plan §15.2 (a draft is its owner's intent log)",
            "open your own draft with `fa draft new <name>`",
        )));
    }
    let extension = intent_bytes(&intent, &req.capability, None, None)?;
    let mut proposal = record_proposal(
        book,
        &view.body,
        Kind::Plan,
        view.body.owner,
        &p.idempotency_key,
        &req,
        Vec::new(),
        vec![(fa_model::entry::DRAFT_INTENT_EXTENSION, extension)],
    )?;
    if proposal.validate().is_err() {
        return Ok(Err(usage(
            "the Plan record is not a valid DraftControl entry",
            "plan the intent with `fa draft plan <name> --intent <file>`",
        )));
    }
    let draft = view.vid;
    let evid = record_vid(book, &proposal);
    // A recorded identity is this Plan's retry, or another intent under the
    // same key: judged before rehearsing, which a retry does not repeat, and
    // before the draft's state, so the retry of a Plan recorded before a
    // promotion or discard still returns its record (FA-INV-09).
    // The intent is judged by the kernel's retry law (plan §4.9), never by
    // the record's bytes: a resubmitted intent reseals its text with fresh
    // salts.
    if let Some(planned) = view.intents.iter().find(|i| i.record == evid) {
        let same = planned.capability == req.capability
            && planned.intent.approvals() == intent.approvals()
            && match (
                planned.intent.proposal().semantic_digest(&book.seal_key),
                p.semantic_digest(&book.seal_key),
            ) {
                (Ok(a), Ok(b)) => a == b,
                _ => planned.intent.proposal().proposal_digest()? == p.proposal_digest()?,
            };
        if !same {
            let row = db
                .vertex(evid)?
                .ok_or_else(|| KernelError::Corrupt("a planned intent's record vanished".into()))?;
            return Ok(Err(conflict_with(&row)));
        }
        return Ok(Ok(DraftPlanned {
            recorded: DraftRecorded {
                draft,
                control_entry: evid,
                recorded_at: planned.recorded_at,
                already_recorded: true,
            },
            plan: None,
        }));
    }
    if view.state != DraftState::Open {
        // Planning into a closed draft: the fix names a fresh draft to plan
        // into instead (which `fa draft new` then opens).
        let mut refusal = not_open(&view.body, view.state);
        if let Some(fresh) = fresh_name(db, book, name)? {
            refusal.fix = format!(
                "open `fa draft new {}` and repeat this command with --draft {fresh}",
                crate::refusal::command_word(&fresh)
            );
            refusal = refusal.or_field_change("draft", vec![fresh]);
        }
        return Ok(Err(refusal));
    }
    if db.vertex(evid)?.is_some() {
        return Err(KernelError::Corrupt(format!(
            "draft `{name}` names no Plan record at {:032x}, which is live",
            evid.0
        )));
    }
    if view.intents.len() >= fa_model::limits::MAX_BATCH_ENTRIES {
        return Ok(Err(usage(
            format!(
                "draft `{name}` already holds {} intents, the most one promotion batch commits",
                view.intents.len()
            ),
            "promote this draft, then plan the rest into a new one",
        )));
    }
    // Rehearse (plan §15.3): each member sees its predecessors' effects.
    let plan =
        match preview_ordered(db, ctx, book, &view, &[(intent.clone(), &req.capability)]).await? {
            Err(refusal) => return Ok(Err(refusal)),
            Ok(plan) => plan,
        };
    let resolved_entry = &plan
        .members()
        .last()
        .ok_or_else(|| KernelError::Corrupt("a draft preview has no candidate".into()))?
        .entry;
    proposal.extensions = vec![(
        fa_model::entry::DRAFT_INTENT_EXTENSION,
        intent_bytes(
            &intent,
            &req.capability,
            Some(resolved_entry.entry_digest),
            Some(resolved_entry),
        )?,
    )];
    if proposal.validate().is_err() {
        return Ok(Err(usage(
            "the reviewed Plan record is not a valid DraftControl entry",
            "reduce the intent's size before planning it into a draft",
        )));
    }
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    if let Err(r) = capability_witness(&txn, db, book, &req.capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    if let Err(r) = witness_open(&txn, db, book, name)? {
        txn.abort();
        return Ok(Err(r));
    }
    if let Err(refusal) = witness_membership(&txn, db, book, &view)? {
        txn.abort();
        return Ok(Err(refusal));
    }
    let entry = proposal.clone().seal(Vec::new(), None)?;
    let mut in_case = WriteBatch::new(relation::IN_CASE);
    in_case.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    in_case.add_edge(edge_id(relation::IN_CASE, evid, draft), evid, draft, vec![]);
    txn.write(db, in_case)?;
    Ok(finish(db, ctx, book, txn, &proposal, draft, evid)
        .await?
        .map(|recorded| DraftPlanned {
            plan: (!recorded.already_recorded).then_some(plan),
            recorded,
        }))
}

/// Discard the open draft `name` (plan §15.2 `DiscardDraft`): its owner, or
/// a reviewer holding `approve`, closes it. Nothing is deleted.
pub async fn discard_draft<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    name: &str,
    req: DraftRequest,
) -> Outcome<DraftRecorded> {
    if let Err(r) = check_name(name) {
        return Ok(Err(r));
    }
    if let Err(r) = admit(db, book, &req.capability, Kind::Discard)? {
        return Ok(Err(r));
    }
    let Some(view) = read_draft(db, &ctx.query(), book, name)? else {
        return Ok(Err(unknown(name)));
    };
    if view.body.owner != req.capability.holder() && !req.capability.holds(Op::Approve) {
        return Ok(Err(denial(&Denial::MissingOp {
            op: Op::Approve,
            what: format!("discarding draft `{name}`, which another principal owns"),
        })));
    }
    let proposal = record_proposal(
        book,
        &view.body,
        Kind::Discard,
        req.capability.holder(),
        &[],
        &req,
        Vec::new(),
        Vec::new(),
    )?;
    let draft = view.vid;
    let evid = record_vid(book, &proposal);
    if let Some(row) = db.vertex(evid)? {
        return Ok(
            recorded_or_conflict(book, &row, &proposal)?.map(|recorded_at| DraftRecorded {
                draft,
                control_entry: evid,
                recorded_at,
                already_recorded: true,
            }),
        );
    }
    if view.state != DraftState::Open {
        return Ok(Err(not_open(&view.body, view.state)));
    }
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    if let Err(r) = capability_witness(&txn, db, book, &req.capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    if let Err(r) = witness_open(&txn, db, book, name)? {
        txn.abort();
        return Ok(Err(r));
    }
    let entry = proposal.clone().seal(Vec::new(), None)?;
    let mut in_case = WriteBatch::new(relation::IN_CASE);
    in_case.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    in_case.compare_and_set_vertex_property(
        draft,
        property::STATE,
        Some(DraftState::Open.scalar()),
        DraftState::Discarded.scalar(),
        WriteMismatchPolicy::AbortWrite,
    );
    in_case.add_edge(edge_id(relation::IN_CASE, evid, draft), evid, draft, vec![]);
    txn.write(db, in_case)?;
    finish(db, ctx, book, txn, &proposal, draft, evid).await
}

/// The batch key of a draft's promotion: one promotion per draft.
fn promotion_key(draft: VId) -> Vec<u8> {
    domain_digest(PROMOTION_KEY_DOMAIN, &[&draft.0.to_le_bytes()]).to_vec()
}

/// Promote the open draft `name` (plan §15.2 `PromoteDraft`): replay every
/// planned intent to trunk in one batch, in planning order, with the
/// Promote record, the `state` move and an `IN_CASE` edge from each
/// promoted entry, all in one commit. The promoter holds `approve` and is
/// not the draft's owner; each intent is admitted again, under its
/// planner's capability, against current trunk. Any refusal promotes
/// nothing. A promoted draft's retry is its recorded promotion.
pub async fn promote_draft<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    name: &str,
    req: DraftRequest,
) -> Outcome<DraftPromoted> {
    if let Err(r) = check_name(name) {
        return Ok(Err(r));
    }
    if let Err(r) = admit(db, book, &req.capability, Kind::Promote)? {
        return Ok(Err(r));
    }
    let Some(view) = read_draft(db, &ctx.query(), book, name)? else {
        return Ok(Err(unknown(name)));
    };
    if view.body.owner == req.capability.holder() {
        return Ok(Err(denial(&Denial::SelfApproval {
            rule: "draft-promote".into(),
            approver: req.capability.holder(),
        })));
    }
    match (view.state, &view.closed) {
        (DraftState::Promoted, Some(closure)) => {
            let Some((outcome, entries)) = closure.promoted.clone() else {
                return Err(KernelError::Corrupt(format!(
                    "promoted draft `{name}` has no recorded promotion outcome"
                )));
            };
            return Ok(Ok(DraftPromoted {
                draft: view.vid,
                control_entry: closure.record,
                outcome,
                entries,
                periods: Vec::new(),
                recorded_at: closure.recorded_at,
                already_recorded: true,
            }));
        }
        (DraftState::Open, _) => {}
        (state, _) => return Ok(Err(not_open(&view.body, state))),
    }
    if view.intents.is_empty() {
        return Ok(Err(usage(
            format!("draft `{name}` has no planned intent to promote"),
            "plan intents into it with `fa draft plan <name> --intent <file>`, or discard it",
        )));
    }
    // The promoter was admitted before any read. Load the immutable close
    // history before replaying the members through the native posting laws.
    if let Err(refusal) = crate::scratch::ensure_history(db, ctx).await? {
        return Ok(Err(refusal));
    }
    let members: Vec<PostIntent> = view.intents.iter().map(|i| i.intent.clone()).collect();
    let capabilities: Vec<Capability> = view.intents.iter().map(|i| i.capability.clone()).collect();
    let batch = match PostBatch::new(promotion_key(view.vid), members) {
        Ok(b) => b,
        Err(e) => {
            return Ok(Err(usage(
                format!("draft `{name}` does not form one batch: {e}"),
                "discard the draft and plan its intents into a new one",
            )));
        }
    };
    let admission = Admission::Promote(Promoting(()));
    let mut staged = match correction::stage(
        db,
        ctx,
        book,
        &capabilities,
        &batch,
        admission,
        correction::is_correction(&view),
    )? {
        Err(refusal) => return Ok(Err(refusal)),
        Ok(staged) => staged,
    };
    if let Err(refusal) = check_resolved_members(name, &view.intents, &staged.entries) {
        staged.abort();
        return Ok(Err(refusal));
    }
    // The promoter's authority is witnessed in the promotion's own
    // transaction, as is the draft's Open state.
    if let Err(r) = capability_witness(staged.txn(), db, book, &req.capability)? {
        staged.abort();
        return Ok(Err(r));
    }
    if let Err(r) = witness_open(staged.txn(), db, book, name)? {
        staged.abort();
        return Ok(Err(r));
    }
    if let Err(refusal) = witness_membership(staged.txn(), db, book, &view)? {
        staged.abort();
        return Ok(Err(refusal));
    }
    let proposal = record_proposal(
        book,
        &view.body,
        Kind::Promote,
        req.capability.holder(),
        &[],
        &req,
        vec![TypedRef::Vertex(staged.outcome)],
        Vec::new(),
    )?;
    let evid = record_vid(book, &proposal);
    if staged.txn().vertex(db, evid)?.is_some() {
        staged.abort();
        return Err(KernelError::Corrupt(format!(
            "draft `{name}` is open but its Promote record already exists"
        )));
    }
    let entry = proposal.clone().seal(Vec::new(), None)?;
    let draft = view.vid;
    let mirrors = entry_mirrors(&entry)?;
    let promoted_entries = staged.entries.clone();
    let (txn, tracker) = staged.parts()?;
    tracker.create_vertex(relation::IN_CASE, evid, 1, &mirrors);
    tracker.set_vertex_property(
        relation::IN_CASE,
        draft,
        property::STATE,
        Some(DraftState::Open.scalar()),
        Some(DraftState::Promoted.scalar()),
    );
    let mut in_case = WriteBatch::new(relation::IN_CASE);
    in_case.create_vertex(evid, vec![label::ENTRY], mirrors);
    in_case.compare_and_set_vertex_property(
        draft,
        property::STATE,
        Some(DraftState::Open.scalar()),
        DraftState::Promoted.scalar(),
        WriteMismatchPolicy::AbortWrite,
    );
    tracker.add_edge(relation::IN_CASE, &[]);
    in_case.add_edge(edge_id(relation::IN_CASE, evid, draft), evid, draft, vec![]);
    for promoted in &promoted_entries {
        let v = promoted.vid;
        tracker.add_edge(relation::IN_CASE, &[]);
        in_case.add_edge(edge_id(relation::IN_CASE, v, draft), v, draft, vec![]);
    }
    txn.write(db, in_case)?;
    if let Err(d) = fa_policy::current(&req.capability, db.frontier()?) {
        staged.abort();
        return Ok(Err(denial(&d)));
    }
    let posted = match staged
        .commit(db, ctx, book, &capabilities, &batch, admission)
        .await?
    {
        Err(refusal) => return Ok(Err(refusal)),
        Ok(posted) => posted,
    };
    Ok(Ok(DraftPromoted {
        draft,
        control_entry: evid,
        outcome: posted.outcome,
        entries: posted.entries,
        periods: posted.periods,
        recorded_at: posted.recorded_at,
        already_recorded: posted.already_recorded,
    }))
}

/// The draft `name` as its records state it at the head.
pub fn read_draft<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    name: &str,
) -> Result<Option<DraftView>, KernelError> {
    let vid = draft_vid(book.book_id, name);
    match db.vertex(vid)? {
        Some(row) if row.labels.contains(&label::DRAFT_SET) => Ok(Some(view_of(db, cx, &row)?)),
        Some(_) => Err(KernelError::Corrupt(format!(
            "draft identity {:032x} holds a vertex that is not a DraftSet",
            vid.0
        ))),
        None => Ok(None),
    }
}

/// Every draft of the book, by opening sequence.
pub fn list_drafts<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
) -> Result<Vec<DraftView>, KernelError> {
    let mut out = Vec::new();
    for row in db.vertices()? {
        if row.labels.contains(&label::DRAFT_SET) {
            let view = view_of(db, cx, &row)?;
            if view.body.book_id == book.book_id {
                out.push(view);
            }
        }
    }
    out.sort_by_key(|v| (v.opened_at, v.vid.0));
    Ok(out)
}

fn view_of<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    row: &VertexRow,
) -> Result<DraftView, KernelError> {
    let draft = row.vid;
    let body = draft_row_body(row)?;
    let state = DraftState::from_scalar(prop(row, property::STATE))
        .ok_or_else(|| KernelError::Corrupt(format!("draft {:032x} state mirror", draft.0)))?;
    let seq = db.frontier()?;
    let mut intents = Vec::new();
    let mut opened_at = None;
    let mut closed = None;
    for edge in db.edges_at(seq)? {
        let e = &edge.entry;
        if e.dst != draft
            || e.relation != relation::IN_CASE
            || e.eid != edge_id(relation::IN_CASE, e.src, draft)
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
        if entry.proposal.class != EntryClass::DRAFT_CONTROL {
            // A promoted entry: listed by its promotion's outcome.
            continue;
        }
        let Some(ControlPayload::LifecycleTransition {
            object_ref,
            from,
            to,
            proof_refs,
            ..
        }) = &entry.proposal.control
        else {
            return Err(KernelError::Corrupt(format!(
                "draft record {:032x} carries no LifecycleTransition",
                e.src.0
            )));
        };
        if *object_ref != draft {
            continue;
        }
        let open = DraftState::Open.tag();
        match (*from, *to) {
            (0, t) if t == open => opened_at = Some(recorded_at),
            (f, t) if f == open && t == open => {
                let Some((_, ext)) = entry
                    .proposal
                    .extensions
                    .iter()
                    .find(|(tag, _)| *tag == fa_model::entry::DRAFT_INTENT_EXTENSION)
                else {
                    return Err(KernelError::Corrupt(format!(
                        "draft Plan record {:032x} carries no intent",
                        e.src.0
                    )));
                };
                for (intent, capability, resolved_entry_digest, resolved_entry) in
                    decode_plan_record(ext)?.members
                {
                    intents.push(PlannedIntent {
                        record: e.src,
                        recorded_at,
                        intent,
                        capability,
                        resolved_entry_digest,
                        resolved_entry,
                    });
                }
            }
            (f, t)
                if f == open
                    && (t == DraftState::Promoted.tag() || t == DraftState::Discarded.tag()) =>
            {
                let promoted = if t == DraftState::Promoted.tag() {
                    let Some(TypedRef::Vertex(outcome)) = proof_refs.first() else {
                        return Err(KernelError::Corrupt(format!(
                            "draft Promote record {:032x} names no outcome",
                            e.src.0
                        )));
                    };
                    let Some((body, _)) = read_outcome(db, cx, *outcome)? else {
                        return Err(KernelError::Corrupt(format!(
                            "draft Promote record {:032x} names a missing outcome",
                            e.src.0
                        )));
                    };
                    Some((*outcome, body.entries))
                } else {
                    None
                };
                closed = Some(DraftClosure {
                    record: e.src,
                    recorded_at,
                    by: entry.proposal.principal_ref,
                    promoted,
                });
            }
            _ => {
                return Err(KernelError::Corrupt(format!(
                    "draft record {:032x} names transition {from} -> {to}",
                    e.src.0
                )));
            }
        }
    }
    // This sort must stay stable: members of a v4 batch share the record
    // and sequence, and their authenticated inner order is their execution order.
    intents.sort_by_key(|i| (i.recorded_at, i.record.0));
    // The row's own created_at starts its current version, which a
    // promotion or discard moves; the Open record is the draft's birth.
    let opened_at = opened_at.ok_or_else(|| {
        KernelError::Corrupt(format!("draft {:032x} has no Open record", draft.0))
    })?;
    let view = DraftView {
        vid: draft,
        body,
        state,
        opened_at,
        intents,
        closed,
    };
    correction::validate_view(&view)?;
    Ok(view)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draft_membership_witness_rejects_both_preexisting_and_concurrent_appends() {
        use asupersync::runtime::RuntimeBuilder;
        use fa_model::{SealKey, SymbolTable};
        use fa_money::UnitRegistry;
        use fa_time::FiscalCalendar;
        use fgdb::DatabaseKeys;
        use fgdb_types::ids::DatabaseSecurityNamespaceId;

        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
        let ctx = PurposeContexts::narrow_runtime_root(&root);
        let mut db = runtime
            .block_on(Database::open_memory(
                &ctx.commit(),
                DatabaseKeys::new([211; 32], DatabaseSecurityNamespaceId([212; 32]), [213; 32]),
            ))
            .unwrap();
        let units = UnitRegistry::with_defaults();
        let book = BookContext {
            book_id: Id128([214; 16]),
            calendar: FiscalCalendar::monthly("draft-membership", 1, 1).unwrap(),
            units: units.clone(),
            seal_key: SealKey([215; 32]),
            symbols: SymbolTable::compiled(),
        };
        let spec = crate::BookSpec {
            book_id: book.book_id,
            name: "Concurrent draft membership".into(),
            base_unit: units.lookup("USD").unwrap(),
            calendar: book.calendar.clone(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        };
        runtime
            .block_on(crate::create_book(
                &mut db,
                &ctx,
                &spec,
                &units,
                &book.symbols,
            ))
            .unwrap();
        let capability = Capability::embedded(VId(7), &["read", "post"]).unwrap();
        let request = DraftRequest {
            capability: capability.clone(),
            effective_date: DateDay::from_ymd(2026, 3, 15).unwrap(),
            description: Erasable::seal(
                &"draft membership".to_string(),
                None,
                &book.seal_key,
                [1; 32],
                [2; 24],
            ),
        };
        runtime
            .block_on(open_draft(&mut db, &ctx, &book, "race", request.clone()))
            .unwrap()
            .unwrap();
        let original = read_draft(&db, &ctx.query(), &book, "race")
            .unwrap()
            .unwrap();
        let planned = |key: &[u8]| {
            let mut proposal = codec_intent().proposal().clone();
            proposal.book_id = book.book_id;
            proposal.idempotency_key = key.to_vec();
            let intent = PostIntent::new(proposal, Vec::new()).unwrap();
            // This is the authentic historical V1 Plan representation; only
            // its membership, never the hypothetical accounting, is published.
            let proposal = record_proposal(
                &book,
                &original.body,
                Kind::Plan,
                capability.holder(),
                key,
                &request,
                Vec::new(),
                vec![(
                    fa_model::entry::DRAFT_INTENT_EXTENSION,
                    intent_bytes(&intent, &capability, None, None).unwrap(),
                )],
            )
            .unwrap();
            let vid = record_vid(&book, &proposal);
            let entry = proposal.seal(Vec::new(), None).unwrap();
            let mut writes = WriteBatch::new(relation::IN_CASE);
            writes.create_vertex(vid, vec![label::ENTRY], entry_mirrors(&entry).unwrap());
            writes.add_edge(
                edge_id(relation::IN_CASE, vid, original.vid),
                vid,
                original.vid,
                vec![],
            );
            (vid, writes)
        };
        let (_, first) = planned(b"first");
        runtime.block_on(db.write(&ctx.commit(), first)).unwrap();
        let txn = db.begin(&ctx.txn()).unwrap();
        // The append happened before this transaction's basis: witnessing the
        // new adjacency without comparing its contents would miss this case.
        let refused = witness_membership(&txn, &db, &book, &original)
            .unwrap()
            .unwrap_err();
        assert_eq!(refused.code, code::CONFLICT);
        txn.abort();

        let reviewed = read_draft(&db, &ctx.query(), &book, "race")
            .unwrap()
            .unwrap();
        let mut pending = db.begin(&ctx.txn()).unwrap();
        witness_membership(&pending, &db, &book, &reviewed)
            .unwrap()
            .unwrap();
        let (candidate, writes) = planned(b"candidate");
        pending.write(&mut db, writes).unwrap();
        let (_, concurrent) = planned(b"concurrent");
        runtime
            .block_on(db.write(&ctx.commit(), concurrent))
            .unwrap();
        let head = db.frontier().unwrap();
        assert!(matches!(
            runtime.block_on(pending.commit(&mut db, &ctx.commit())),
            Err(WriteTxnError::Write(
                fgdb::WriteError::FirstCommitterWins { .. }
            ))
        ));
        assert_eq!(db.frontier().unwrap(), head);
        assert!(db.vertex(candidate).unwrap().is_none());
    }

    pub(super) fn codec_intent() -> PostIntent {
        use fa_model::{LegPayload, Oid, SealKey};
        use fa_money::{Amount, Side, UnitRegistry};

        let unit = UnitRegistry::with_defaults().lookup("USD").unwrap();
        let legs = vec![
            LegPayload::simple(Side::Debit, VId(1), Amount::new(unit, 100)),
            LegPayload::simple(Side::Credit, VId(2), Amount::new(unit, 100)),
        ];
        let proposal = EntryPayload {
            schema_minor: fa_model::entry::SCHEMA_MINOR,
            book_id: Id128([7; 16]),
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: DateDay::from_ymd(2026, 3, 15).unwrap(),
            document_date: None,
            description: Erasable::seal(
                &"retained draft codec".to_string(),
                None,
                &SealKey([1; 32]),
                [2; 32],
                [3; 24],
            ),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: b"retained-entry".to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([4; 32]),
                intent_kind: 1,
            },
            principal_ref: VId(7),
            session_ref: None,
            evidence: Vec::new(),
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        };
        PostIntent::new(proposal, Vec::new()).unwrap()
    }

    #[test]
    fn draft_intent_versions_keep_canonical_bytes_and_v3_deduplicates_exact_entries() {
        let intent = codec_intent();
        let capability = Capability::embedded(VId(7), &["post"]).unwrap();
        let entry = intent.proposal().clone().seal(Vec::new(), None).unwrap();
        for version in [1, 2, 3] {
            let digest = (version >= 2).then_some(entry.entry_digest);
            let resolved = (version == 3).then_some(&entry);
            let bytes = intent_bytes(&intent, &capability, digest, resolved).unwrap();
            assert_eq!(&bytes[..2], &u16::to_le_bytes(version));
            let (read_intent, read_cap, read_digest, read_entry) = decode_intent(&bytes).unwrap();
            assert_eq!(read_intent, intent);
            assert_eq!(read_cap, capability);
            assert_eq!(read_digest, digest);
            assert_eq!(read_entry.as_ref(), resolved);
            assert_eq!(
                intent_bytes(&read_intent, &read_cap, read_digest, read_entry.as_ref()).unwrap(),
                bytes
            );
            if version == 3 {
                let old = intent_bytes(&intent, &capability, digest, None).unwrap();
                assert_eq!(bytes.len(), old.len() + 4);
                assert_eq!(&bytes[bytes.len() - 4..], &[0; 4]);
            }
        }
    }

    #[test]
    fn retained_draft_entry_codec_rejects_tampering_noncanonical_and_unrelated_entries() {
        let original = codec_intent();
        let capability = Capability::embedded(VId(7), &["post"]).unwrap();
        let intent = PostIntent::new(
            crate::limit::balancing_proposal(original.proposal().clone(), 1).unwrap(),
            Vec::new(),
        )
        .unwrap();
        let mut proposal = intent.proposal().clone();
        for leg in &mut proposal.legs {
            leg.amount.mantissa = 40;
        }
        proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
        let entry = proposal.seal(Vec::new(), None).unwrap();
        let bytes =
            intent_bytes(&intent, &capability, Some(entry.entry_digest), Some(&entry)).unwrap();
        let decoded = decode_intent(&bytes).unwrap();
        assert_eq!(decoded.3.as_ref(), Some(&entry));
        assert_eq!(
            intent_bytes(&decoded.0, &decoded.1, decoded.2, decoded.3.as_ref()).unwrap(),
            bytes
        );
        for end in 0..bytes.len() {
            assert!(decode_intent(&bytes[..end]).is_err(), "truncation at {end}");
        }
        let mut changed = bytes.clone();
        let last = changed.len() - 1;
        changed[last] ^= 1;
        assert!(decode_intent(&changed).is_err());
        let encode_raw = |digest: [u8; 32], resolved: &[u8]| {
            let mut w = Writer::new();
            w.u16(3)
                .bytes(&intent.canonical_bytes().unwrap())
                .bytes(&capability.canonical_bytes().unwrap())
                .fixed(&digest)
                .bytes(resolved);
            w.finish().unwrap()
        };
        assert!(decode_intent(&encode_raw([0; 32], &entry.encode().unwrap())).is_err());
        assert!(decode_intent(&encode_raw(entry.entry_digest, &[])).is_err());
        let duplicate = intent.proposal().clone().seal(Vec::new(), None).unwrap();
        assert!(
            decode_intent(&encode_raw(
                duplicate.entry_digest,
                &duplicate.encode().unwrap()
            ))
            .is_err()
        );
        let mut unrelated = entry.proposal.clone();
        unrelated.idempotency_key = b"different-request".to_vec();
        let unrelated = unrelated.seal(Vec::new(), None).unwrap();
        assert!(
            decode_intent(&encode_raw(
                unrelated.entry_digest,
                &unrelated.encode().unwrap()
            ))
            .is_err()
        );
    }

    #[test]
    fn draft_bodies_round_trip_and_bind_every_field() {
        let body = DraftBody {
            book_id: Id128([7; 16]),
            name: "close-03".into(),
            owner: VId(42),
        };
        let bytes = body.canonical_bytes().unwrap();
        assert_eq!(DraftBody::decode(&bytes).unwrap(), body);
        for end in 0..bytes.len() {
            assert!(DraftBody::decode(&bytes[..end]).is_err(), "prefix {end}");
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(DraftBody::decode(&trailing).is_err());
        let renamed = DraftBody {
            name: "close-04".into(),
            ..body.clone()
        };
        assert_ne!(renamed.digest().unwrap(), body.digest().unwrap());
        assert_ne!(renamed.vid(), body.vid());
        let reowned = DraftBody {
            owner: VId(43),
            ..body.clone()
        };
        assert_ne!(reowned.digest().unwrap(), body.digest().unwrap());
        assert_eq!(reowned.vid(), body.vid(), "one draft per name in a book");
    }

    #[test]
    fn record_keys_separate_kinds_drafts_and_intents_within_the_key_bound() {
        let a = VId(1);
        let b = VId(2);
        let keys = [
            record_key(Kind::Open, a, &[]),
            record_key(Kind::Plan, a, b"k1"),
            record_key(Kind::Plan, a, b"k2"),
            record_key(Kind::Plan, b, b"k1"),
            record_key(Kind::Promote, a, &[]),
            record_key(Kind::Discard, a, &[]),
        ];
        for (i, k) in keys.iter().enumerate() {
            assert!(k.len() <= fa_model::limits::MAX_IDEMPOTENCY_KEY_BYTES);
            for other in &keys[i + 1..] {
                assert_ne!(k, other);
            }
        }
        assert_ne!(promotion_key(a), promotion_key(b));
    }

    #[test]
    fn draft_states_round_trip_through_their_scalars() {
        for s in [
            DraftState::Open,
            DraftState::Promoted,
            DraftState::Discarded,
        ] {
            assert_eq!(DraftState::from_scalar(Some(&s.scalar())), Some(s));
        }
        assert_eq!(
            DraftState::from_scalar(Some(&CanonicalScalar::Int(0))),
            None
        );
        assert_eq!(DraftState::from_scalar(None), None);
    }
}
