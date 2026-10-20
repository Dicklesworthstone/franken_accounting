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
//!   `fa:draft-intent:v1`: the `PostIntent`'s canonical bytes and the
//!   planner's capability). The intent is rehearsed through the real posting
//!   pipeline first ([`crate::plan::plan_post`]); one the kernel would refuse
//!   never enters the draft. Its identity derives from the draft and the
//!   intent's key, so a retry is its recorded outcome.
//! - **Promote** (`Open → Promoted`) replays the planned intents to trunk in
//!   one `PostBatch`, in planning order, in the same transaction as the
//!   record (FA-INV-09). The promoter holds `approve` (the `draft-promote`
//!   row; no Agent- or System-profile capability can) and is never the
//!   draft's owner. Each intent posts under its planner's own capability,
//!   every admission check of which runs again against current trunk —
//!   period law, ceilings, scope, revocation, evidence — except the Agent's
//!   trunk denial, which the promoter's authority answers
//!   ([`crate::post::Admission::Promote`]). The promoted entries keep the
//!   planner as their principal and point at the draft by `IN_CASE`.
//! - **Discard** (`Open → Discarded`) closes the draft; nothing is deleted.
//!
//! Every record moves or witnesses `state` in its own transaction, so a
//! Promote and a Discard (or a Plan) racing on one draft are a
//! first-committer-wins conflict. Nothing in a draft is a trunk entry until
//! its promotion commits.

use fa_intents::{PostBatch, PostIntent, PostPlan};
use fa_model::symbols::{label, property, relation};
use fa_model::{
    ControlKind, ControlPayload, EntryClass, EntryOrigin, EntryPayload, EntryRef, Erasable, Id128,
    Reader, TypedRef, Writer, domain_digest, draft_vid, entry_mirrors, entry_vid,
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

mod rehearsal;
pub(crate) use rehearsal::Rehearsing;
pub use rehearsal::{
    DraftRehearsal, DraftRehearsalRequest, DraftRehearsalSource, DraftSourceRecord,
    rehearse_draft_into,
};

/// Canonical bytes of a draft body: `u16 version ‖ book_id[16] ‖ str name ‖
/// u128 owner_principal` (extension 8).
pub const DRAFT_BODY_VERSION: u16 = 1;
/// Canonical bytes of a planned intent: `u16 version ‖ bytes post_intent ‖
/// bytes capability` (extension 9).
pub const DRAFT_INTENT_VERSION: u16 = 1;
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
}

fn intent_bytes(intent: &PostIntent, capability: &Capability) -> Result<Vec<u8>, KernelError> {
    let intent = intent.canonical_bytes().map_err(intent_error)?;
    let capability = capability
        .canonical_bytes()
        .map_err(|e| KernelError::Corrupt(format!("capability bytes: {e}")))?;
    let mut w = Writer::with_capacity(8 + intent.len() + capability.len());
    w.u16(DRAFT_INTENT_VERSION)
        .bytes(&intent)
        .bytes(&capability);
    Ok(w.finish()?)
}

fn decode_intent(bytes: &[u8]) -> Result<(PostIntent, Capability), KernelError> {
    let mut r = Reader::new(bytes);
    if r.u16("draft_intent.version").map_err(decode)? != DRAFT_INTENT_VERSION {
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
    r.finish().map_err(decode)?;
    Ok((intent, capability))
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

/// A recorded Plan: the record, and the rehearsal it passed (absent on a
/// recorded retry, which rehearses nothing).
#[derive(Clone, Debug)]
pub struct DraftPlanned {
    pub recorded: DraftRecorded,
    pub plan: Option<PostPlan>,
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
    Promote,
    Discard,
}

impl Kind {
    fn transition(self) -> &'static str {
        match self {
            Self::Open => "Open",
            Self::Plan => "Plan",
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
        }
    }

    fn states(self) -> (u8, DraftState) {
        match self {
            Self::Open => (0, DraftState::Open),
            Self::Plan => (DraftState::Open.tag(), DraftState::Open),
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
        schema_minor: fa_model::entry::SCHEMA_MINOR,
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
        "list the book's drafts with `fa draft list --json`, or open one with `fa draft new <name>`",
    )
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

/// Plan `intent` into the open draft `name` (plan §15.2 `plan_in_draft`):
/// rehearse it through the real posting pipeline, then journal it as one
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
    let extension = intent_bytes(&intent, &req.capability)?;
    let proposal = record_proposal(
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
        return Ok(Err(not_open(&view.body, view.state)));
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
    // Rehearse (plan §15.3): every posting law at the head; nothing staged.
    let plan =
        match crate::plan::plan_post_with_history(db, ctx, book, req.capability.clone(), intent)
            .await?
        {
            Err(refusal) => return Ok(Err(refusal)),
            Ok(plan) => plan,
        };
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
    let mut staged = match stage_batch(db, ctx, book, &capabilities, &batch, admission)? {
        Err(refusal) => return Ok(Err(refusal)),
        Ok(BatchStage::Recorded(_)) => {
            return Err(KernelError::Corrupt(format!(
                "draft `{name}` is open but its promotion batch is already recorded"
            )));
        }
        Ok(BatchStage::Staged(staged)) => staged,
    };
    // The promoter's authority is witnessed in the promotion's own
    // transaction, as is the draft's Open state.
    if let Err(r) = capability_witness(&staged.txn, db, book, &req.capability)? {
        staged.txn.abort();
        return Ok(Err(r));
    }
    if let Err(r) = witness_open(&staged.txn, db, book, name)? {
        staged.txn.abort();
        return Ok(Err(r));
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
    if staged.txn.vertex(db, evid)?.is_some() {
        staged.txn.abort();
        return Err(KernelError::Corrupt(format!(
            "draft `{name}` is open but its Promote record already exists"
        )));
    }
    let entry = proposal.clone().seal(Vec::new(), None)?;
    let draft = view.vid;
    let mut in_case = WriteBatch::new(relation::IN_CASE);
    in_case.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    in_case.compare_and_set_vertex_property(
        draft,
        property::STATE,
        Some(DraftState::Open.scalar()),
        DraftState::Promoted.scalar(),
        WriteMismatchPolicy::AbortWrite,
    );
    in_case.add_edge(edge_id(relation::IN_CASE, evid, draft), evid, draft, vec![]);
    for promoted in &staged.entries {
        let v = promoted.vid;
        in_case.add_edge(edge_id(relation::IN_CASE, v, draft), v, draft, vec![]);
    }
    staged.txn.write(db, in_case)?;
    if let Err(d) = fa_policy::current(&req.capability, db.frontier()?) {
        staged.txn.abort();
        return Ok(Err(denial(&d)));
    }
    let posted = match commit_batch(db, ctx, book, &capabilities, &batch, admission, staged).await?
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
                let (intent, capability) = decode_intent(ext)?;
                intents.push(PlannedIntent {
                    record: e.src,
                    recorded_at,
                    intent,
                    capability,
                });
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
    intents.sort_by_key(|i| (i.recorded_at, i.record.0));
    // The row's own created_at starts its current version, which a
    // promotion or discard moves; the Open record is the draft's birth.
    let opened_at = opened_at.ok_or_else(|| {
        KernelError::Corrupt(format!("draft {:032x} has no Open record", draft.0))
    })?;
    Ok(DraftView {
        vid: draft,
        body,
        state,
        opened_at,
        intents,
        closed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
