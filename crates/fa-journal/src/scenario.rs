//! Scenarios (plan §15.2 "Drafts, branches, and scenarios", Appendix B
//! `ForkScenario`, Appendix H R-BR interim posture; bead fa-k07b).
//!
//! A scenario is a counterfactual over a fixed trunk prefix. Until substrate
//! branches ship it is "a deterministic replay of the trunk journal plus
//! scenario intents into a scratch book" (plan §15.2), which the facade
//! materializes. Its history is exactly its `ScenarioControl` records (class
//! 26, control kind 12), each a `LifecycleTransition` on the `Scenario`
//! vertex at [`fa_model::scenario_vid`]:
//!
//! - **Open** (`0 → Open`) journals the immutable body (extension 10
//!   `fa:scenario-body:v1`: book, name, owner, the trunk sequence it forks
//!   at and the optional date its counterfactual starts) and names its
//!   assumption documents as proof refs; it creates the vertex with
//!   `state = Open`.
//! - **Plan** (`Open → Open`) journals one counterfactual intent (extension
//!   11 `fa:scenario-intent:v1`: the `PostIntent`'s canonical bytes and the
//!   planner's capability). The kernel checks its shape here: the owner's,
//!   for this book's trunk, a batchable class, effective on or after the
//!   start date, under a key no other intent in the scenario holds. The
//!   facade rehearses it on the scenario's materialization before recording
//!   it, and every materialization posts it again under every posting law.
//! - **Discard** (`Open → Discarded`) closes the scenario; nothing is
//!   deleted.
//!
//! Nothing in a scenario is a trunk entry and a scenario is never promoted.
//! Its fork sequence fixes the trunk prefix it replays, so later trunk
//! commits never change what it computes.

use fa_intents::PostIntent;
use fa_model::symbols::{label, property, relation};
use fa_model::{
    ControlKind, ControlPayload, EntryClass, EntryOrigin, EntryPayload, Erasable, Id128, Oid,
    Reader, TypedRef, Writer, domain_digest, entry_mirrors, entry_vid, scenario_vid,
};
use fa_policy::{Capability, Denial, Intent, Op};
use fa_time::DateDay;
use fgdb::{Database, VertexRow, WriteBatch, WriteMismatchPolicy, WriteTxn, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::draft::PlannedIntent;
use crate::evidence::document_vid;
use crate::genesis::BookContext;
use crate::policy::{capability_witness, refusal as denial, steward};
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{bytes, edge_id, prop, scalar_bytes, scalar_text};

/// Canonical bytes of a scenario body: `u16 version ‖ book_id[16] ‖ str
/// name ‖ u128 owner_principal ‖ u64 fork_at ‖ bool has_from ‖ [i32
/// from_day]` (extension 10).
pub const SCENARIO_BODY_VERSION: u16 = 1;
/// Canonical bytes of a counterfactual intent: `u16 version ‖ bytes
/// post_intent ‖ bytes capability` (extension 11).
pub const SCENARIO_INTENT_VERSION: u16 = 1;
/// A scenario name's bound, in bytes.
pub const MAX_SCENARIO_NAME_BYTES: usize = 128;
/// The most assumption documents one scenario names.
pub const MAX_SCENARIO_ASSUMPTIONS: usize = 256;
const SCENARIO_BODY_DOMAIN: &[u8] = b"fa:scenario-body:v1";
const RECORD_KEY_DOMAIN: &[u8] = b"fa:scenario-record-key:v1";
const CITE: &str = "plan §15.2, Appendix B ForkScenario (bead fa-k07b)";

/// The `state` projection of a `Scenario` (lifecycle-by-transition).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScenarioState {
    Open,
    Discarded,
}

impl ScenarioState {
    /// The `LifecycleTransition` state tag; 0 is "no scenario yet".
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            Self::Open => 1,
            Self::Discarded => 2,
        }
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Discarded => "discarded",
        }
    }

    fn scalar(self) -> CanonicalScalar {
        CanonicalScalar::Int(i64::from(self.tag()))
    }

    pub(crate) fn from_scalar(v: Option<&CanonicalScalar>) -> Option<Self> {
        match v {
            Some(CanonicalScalar::Int(1)) => Some(Self::Open),
            Some(CanonicalScalar::Int(2)) => Some(Self::Discarded),
            _ => None,
        }
    }
}

/// A scenario's immutable body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScenarioBody {
    pub book_id: Id128,
    pub name: String,
    pub owner: VId,
    /// The trunk commit sequence the scenario replays.
    pub fork_at: CommitSeq,
    /// The effective date its counterfactual starts: every intent is
    /// effective on or after it.
    pub from: Option<DateDay>,
}

impl ScenarioBody {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, KernelError> {
        let mut w = Writer::with_capacity(64 + self.name.len());
        w.u16(SCENARIO_BODY_VERSION)
            .fixed(&self.book_id.0)
            .str(&self.name)
            .u128(self.owner.0)
            .u64(self.fork_at.0)
            .bool(self.from.is_some());
        if let Some(from) = self.from {
            w.i32(from.0);
        }
        Ok(w.finish()?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, KernelError> {
        let mut r = Reader::new(bytes);
        if r.u16("scenario.version").map_err(decode)? != SCENARIO_BODY_VERSION {
            return Err(KernelError::Corrupt(
                "unsupported scenario body version".into(),
            ));
        }
        let book_id = Id128(r.fixed("scenario.book_id").map_err(decode)?);
        let name = r
            .str(MAX_SCENARIO_NAME_BYTES, "scenario.name")
            .map_err(decode)?
            .to_string();
        let owner = VId(r.u128("scenario.owner").map_err(decode)?);
        let fork_at = CommitSeq(r.u64("scenario.fork_at").map_err(decode)?);
        let from = if r.bool("scenario.has_from").map_err(decode)? {
            Some(DateDay(r.i32("scenario.from").map_err(decode)?))
        } else {
            None
        };
        r.finish().map_err(decode)?;
        Ok(Self {
            book_id,
            name,
            owner,
            fork_at,
            from,
        })
    }

    pub fn digest(&self) -> Result<[u8; 32], KernelError> {
        Ok(domain_digest(
            SCENARIO_BODY_DOMAIN,
            &[&self.canonical_bytes()?],
        ))
    }

    #[must_use]
    pub fn vid(&self) -> VId {
        scenario_vid(self.book_id, &self.name)
    }
}

fn intent_bytes(intent: &PostIntent, capability: &Capability) -> Result<Vec<u8>, KernelError> {
    let intent = intent.canonical_bytes().map_err(intent_error)?;
    let capability = capability
        .canonical_bytes()
        .map_err(|e| KernelError::Corrupt(format!("capability bytes: {e}")))?;
    let mut w = Writer::with_capacity(8 + intent.len() + capability.len());
    w.u16(SCENARIO_INTENT_VERSION)
        .bytes(&intent)
        .bytes(&capability);
    Ok(w.finish()?)
}

fn decode_intent(bytes: &[u8]) -> Result<(PostIntent, Capability), KernelError> {
    let mut r = Reader::new(bytes);
    if r.u16("scenario_intent.version").map_err(decode)? != SCENARIO_INTENT_VERSION {
        return Err(KernelError::Corrupt(
            "unsupported scenario intent version".into(),
        ));
    }
    let intent = PostIntent::decode(
        r.bytes(fa_model::limits::MAX_ENTRY_BYTES, "scenario_intent.intent")
            .map_err(decode)?,
    )
    .map_err(intent_error)?;
    let capability = Capability::decode(
        r.bytes(64 * 1024, "scenario_intent.capability")
            .map_err(decode)?,
    )
    .map_err(|e| KernelError::Corrupt(format!("scenario intent capability: {e}")))?;
    r.finish().map_err(decode)?;
    Ok((intent, capability))
}

fn decode(e: fa_model::DecodeError) -> KernelError {
    KernelError::Model(e.into())
}

fn intent_error(e: fa_intents::IntentError) -> KernelError {
    KernelError::Corrupt(format!("scenario intent: {e}"))
}

/// A scenario as its records state it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScenarioView {
    pub vid: VId,
    pub body: ScenarioBody,
    pub state: ScenarioState,
    pub opened_at: CommitSeq,
    /// The Open record's assumption documents, in canonical order.
    pub assumptions: Vec<Oid>,
    /// In planning order: the order every materialization posts them.
    pub intents: Vec<PlannedIntent>,
    /// The Discard record, and the principal who made it.
    pub discarded: Option<ScenarioClosure>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScenarioClosure {
    pub record: VId,
    pub recorded_at: CommitSeq,
    pub by: VId,
}

/// A scenario control request: the acting capability, the record's (undated,
/// book-scoped) effective date and its sealed description.
#[derive(Clone, Debug)]
pub struct ScenarioRequest {
    pub capability: Capability,
    pub effective_date: DateDay,
    pub description: Erasable<String>,
}

/// What an Open names besides the scenario's name.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScenarioFork {
    /// The trunk sequence to replay; `None` is the head when the scenario
    /// opens (a retry keeps the recorded sequence).
    pub at: Option<CommitSeq>,
    /// The effective date the counterfactual starts.
    pub from: Option<DateDay>,
    /// Documents the scenario's assumptions rest on; each is held by the
    /// book.
    pub assumptions: Vec<Oid>,
}

/// One recorded scenario control (Open, Plan or Discard).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScenarioRecorded {
    pub scenario: VId,
    pub control_entry: VId,
    pub recorded_at: CommitSeq,
    /// The same record was already journaled (FA-INV-09): nothing written.
    pub already_recorded: bool,
}

#[derive(Clone, Copy)]
enum Kind {
    Open,
    Plan,
    Discard,
}

impl Kind {
    fn transition(self) -> &'static str {
        match self {
            Self::Open => "Open",
            Self::Plan => "Plan",
            Self::Discard => "Discard",
        }
    }

    fn tag(self) -> u8 {
        match self {
            Self::Open => 0,
            Self::Plan => 1,
            Self::Discard => 2,
        }
    }

    fn states(self) -> (u8, ScenarioState) {
        match self {
            Self::Open => (0, ScenarioState::Open),
            Self::Plan => (ScenarioState::Open.tag(), ScenarioState::Open),
            Self::Discard => (ScenarioState::Open.tag(), ScenarioState::Discarded),
        }
    }
}

/// A record's idempotency key: `H(domain ‖ kind ‖ scenario ‖
/// discriminator)`, within the key bound whatever the intent's own key.
fn record_key(kind: Kind, scenario: VId, discriminator: &[u8]) -> Vec<u8> {
    domain_digest(
        RECORD_KEY_DOMAIN,
        &[&[kind.tag()], &scenario.0.to_le_bytes(), discriminator],
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
    body: &ScenarioBody,
    kind: Kind,
    principal: VId,
    discriminator: &[u8],
    req: &ScenarioRequest,
    proof_refs: Vec<TypedRef>,
    extensions: Vec<(u16, Vec<u8>)>,
) -> Result<EntryPayload, KernelError> {
    let scenario = body.vid();
    let (from, to) = kind.states();
    Ok(EntryPayload {
        schema_minor: fa_model::entry::SCHEMA_MINOR,
        book_id: book.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::SCENARIO_CONTROL,
        effective_date: req.effective_date,
        document_date: None,
        description: req.description.clone(),
        effective_period: None,
        legs: Vec::new(),
        control: Some(ControlPayload::LifecycleTransition {
            object_ref: scenario,
            from,
            to: to.tag(),
            proof_refs,
            reason_code: 0,
        }),
        unit_totals: Vec::new(),
        base_totals: None,
        idempotency_key: record_key(kind, scenario, discriminator),
        origin: EntryOrigin::Control {
            control_kind: ControlKind::SCENARIO_TRANSITION,
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

/// Authority before any read (doctrine 8): the `ScenarioControl` row's
/// preparer op for `kind`, held by the acting principal, current at the
/// head. A scenario record is not a trunk entry, so an Agent may fork, run
/// and discard its scenario.
fn admit<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    capability: &Capability,
    kind: Kind,
) -> Outcome<()> {
    let op = steward()?
        .transition_op("ScenarioControl", kind.transition())
        .ok_or_else(|| {
            KernelError::Corrupt(format!(
                "sod_policy.toml registers no ScenarioControl {} rule; the record is refused, never unconstrained",
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
    Refusal::new(code::STRUCTURE, exit::USAGE, message.into(), CITE, fix)
}

fn unknown(name: &str) -> Refusal {
    Refusal::new(
        code::SCENARIO_UNKNOWN,
        exit::REFUSAL,
        format!("this book has no scenario named `{name}`"),
        "plan §15.2 (scenarios; bead fa-k07b)",
        format!(
            "list the book's scenarios with `fa scenario list --json`, or fork this one with `fa scenario fork {}`",
            crate::refusal::command_word(name)
        ),
    )
    .at("scenario", name)
}

/// The first `<name>-<n>` (n in 2..=64) that names no scenario yet, within
/// the name bound: the fresh scenario a closed scenario's fix runs in.
fn fresh_name<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    name: &str,
) -> Result<Option<String>, KernelError> {
    for n in 2..=64u32 {
        let candidate = format!("{name}-{n}");
        if candidate.len() > MAX_SCENARIO_NAME_BYTES {
            return Ok(None);
        }
        if db.vertex(scenario_vid(book.book_id, &candidate))?.is_none() {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

fn not_open(body: &ScenarioBody, state: ScenarioState) -> Refusal {
    Refusal::new(
        code::SCENARIO_NOT_OPEN,
        exit::REFUSAL,
        format!(
            "scenario `{}` is {}: it takes no further records",
            body.name,
            state.name()
        ),
        "plan §15.2 (a discarded scenario is closed; its history is immutable)",
        "fork a new scenario with `fa scenario fork <name>` and run its intents there",
    )
}

fn check_name(name: &str) -> Result<(), Refusal> {
    if name.is_empty()
        || name.len() > MAX_SCENARIO_NAME_BYTES
        || name.trim() != name
        || name.chars().any(char::is_control)
    {
        return Err(usage(
            "a scenario name is 1..=128 bytes with no surrounding whitespace or control characters",
            "fa scenario fork <name>   (for example but-for-breach)",
        ));
    }
    Ok(())
}

fn conflict_with(row: &VertexRow) -> Refusal {
    Refusal::new(
        code::IDEMPOTENCY_CONFLICT,
        exit::CONFLICT,
        format!(
            "this scenario record's identity holds different content; the recorded entry is {:032x}",
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
                    "the recorded scenario record {:032x} has erased text, so a retry cannot be judged identical",
                    row.vid.0
                ),
                "plan §4.9, §14.6 (erasure leaves identity, not plaintext)",
                "use a new name or intent key",
            )))
        }
        (Err(e), _) | (_, Err(e)) => Err(e.into()),
    }
}

fn scenario_row_body(row: &VertexRow) -> Result<ScenarioBody, KernelError> {
    ScenarioBody::decode(&bytes(row, property::FA_PAYLOAD, "scenario._fa_payload")?)
}

/// Witness the scenario inside `txn` (a property-granular point read of its
/// state): a Discard that commits first makes this transaction a
/// first-committer-wins conflict.
fn witness_open<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    book: &BookContext,
    name: &str,
) -> Outcome<ScenarioBody> {
    let vid = scenario_vid(book.book_id, name);
    let Some(row) = txn.vertex(db, vid)? else {
        return Ok(Err(unknown(name)));
    };
    if !row.labels.contains(&label::SCENARIO) {
        return Err(KernelError::Corrupt(format!(
            "scenario identity {:032x} holds a vertex that is not a Scenario",
            vid.0
        )));
    }
    let body = scenario_row_body(&row)?;
    let state = ScenarioState::from_scalar(txn.vertex_property(db, vid, property::STATE)?.as_ref())
        .ok_or_else(|| KernelError::Corrupt(format!("scenario {:032x} state mirror", vid.0)))?;
    if state != ScenarioState::Open {
        return Ok(Err(not_open(&body, state)));
    }
    Ok(Ok(body))
}

fn fcw(detail: &str) -> Refusal {
    Refusal::new(
        code::CONFLICT,
        exit::CONFLICT,
        format!("a concurrent commit invalidated a witness this scenario record read: {detail}"),
        "FG-LAW-FCW-01 (first committer wins)",
        "retry; if the scenario was discarded meanwhile, the retry says so",
    )
}

/// Commit a scenario record's transaction, mapping the substrate's outcomes.
async fn finish<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    mut txn: WriteTxn,
    proposal: &EntryPayload,
    scenario: VId,
    control_entry: VId,
) -> Outcome<ScenarioRecorded> {
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(ScenarioRecorded {
            scenario,
            control_entry,
            recorded_at: seq,
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(fcw(&detail)))
        }
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => match db.vertex(control_entry)? {
            Some(row) => Ok(
                recorded_or_conflict(book, &row, proposal)?.map(|recorded_at| ScenarioRecorded {
                    scenario,
                    control_entry,
                    recorded_at,
                    already_recorded: true,
                }),
            ),
            None => Err(KernelError::Corrupt(
                "scenario record identity spent but no live row".into(),
            )),
        },
        Err(e) => Err(e.into()),
    }
}

/// The assumption documents in canonical order, each held by the book.
fn assumptions<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    requested: &[Oid],
) -> Outcome<Vec<Oid>> {
    if requested.len() > MAX_SCENARIO_ASSUMPTIONS {
        return Ok(Err(usage(
            format!("a scenario names at most {MAX_SCENARIO_ASSUMPTIONS} assumption documents"),
            "cite the documents the counterfactual rests on; bundle the rest into one document",
        )));
    }
    let mut sorted = requested.to_vec();
    sorted.sort_unstable_by_key(|o| o.0);
    sorted.dedup();
    if sorted.len() != requested.len() {
        return Ok(Err(usage(
            "an assumption document is named twice",
            "name each assumption document once with --evidence <oid>",
        )));
    }
    for oid in &sorted {
        let held = db
            .vertex(document_vid(oid))?
            .is_some_and(|row| row.labels.contains(&label::DOCUMENT));
        if !held {
            return Ok(Err(Refusal::new(
                code::EVIDENCE_UNKNOWN,
                exit::REFUSAL,
                format!(
                    "assumption document {} is not held by this book",
                    crate::evidence::hex(&oid.0)
                ),
                "plan §15.6.5 (a but-for scenario names every assumption document)",
                "add the document first with `fa document add <file>`, then cite the oid it prints",
            )));
        }
    }
    Ok(Ok(sorted))
}

/// Open the scenario `name` owned by the capability's holder: one commit
/// journaling the Open record (its assumption documents as proof refs), the
/// `Scenario` vertex with its immutable body and `state = Open`, and the
/// record's `IN_CASE` edge to it. The fork sequence is a commit of this
/// book's history at or after its genesis.
pub async fn open_scenario<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    name: &str,
    fork: ScenarioFork,
    req: ScenarioRequest,
) -> Outcome<ScenarioRecorded> {
    if let Err(r) = check_name(name) {
        return Ok(Err(r));
    }
    if let Err(r) = admit(db, book, &req.capability, Kind::Open)? {
        return Ok(Err(r));
    }
    let assumptions = match assumptions(db, &fork.assumptions)? {
        Ok(a) => a,
        Err(r) => return Ok(Err(r)),
    };
    let owner = req.capability.holder();
    let head = db.frontier()?;
    // A retry without --at keeps the sequence its scenario recorded.
    let fork_at = match (fork.at, read_scenario(db, book, name)?) {
        (Some(at), _) => at,
        (None, Some(existing)) if existing.body.owner == owner => existing.body.fork_at,
        (None, _) => head,
    };
    // A reopened directory book holds only its frontier in the delta window;
    // the genesis and every later materialization read history from the
    // start. A store whose history is not retained cannot hold a scenario,
    // so it refuses here rather than at the first run.
    if let Err(r) = crate::scratch::ensure_history(db, ctx).await? {
        return Ok(Err(r));
    }
    let genesis = crate::scratch::source_genesis(db)?
        .ok_or_else(|| KernelError::Corrupt("the book has no genesis commit".into()))?;
    if fork_at < genesis || fork_at > head {
        return Ok(Err(usage(
            format!(
                "fork sequence {} is outside this book's history ({}..={})",
                fork_at.0, genesis.0, head.0
            ),
            "fork at HEAD or at a sequence a known-at read printed (fa scenario fork <name> --at <seq>)",
        )));
    }
    let body = ScenarioBody {
        book_id: book.book_id,
        name: name.to_string(),
        owner,
        fork_at,
        from: fork.from,
    };
    let body_bytes = body.canonical_bytes()?;
    let proposal = record_proposal(
        book,
        &body,
        Kind::Open,
        owner,
        &[],
        &req,
        assumptions.iter().map(|o| TypedRef::Object(*o)).collect(),
        vec![(fa_model::entry::SCENARIO_BODY_EXTENSION, body_bytes.clone())],
    )?;
    if proposal.validate().is_err() {
        return Ok(Err(usage(
            "the Open record is not a valid ScenarioControl entry",
            "fork the scenario with `fa scenario fork <name>`",
        )));
    }
    let scenario = body.vid();
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
            recorded_or_conflict(book, &row, &proposal)?.map(|recorded_at| ScenarioRecorded {
                scenario,
                control_entry: evid,
                recorded_at,
                already_recorded: true,
            }),
        );
    }
    if let Some(existing) = txn.vertex(db, scenario)? {
        txn.abort();
        let held = scenario_row_body(&existing)
            .ok()
            .map_or_else(String::new, |b| {
                format!(
                    " (forked at {} by principal {:032x})",
                    b.fork_at.0, b.owner.0
                )
            });
        return Ok(Err(Refusal::new(
            code::IDEMPOTENCY_CONFLICT,
            exit::CONFLICT,
            format!("scenario `{name}` already exists{held}"),
            "plan §15.2 (one scenario per name in a book)",
            "choose another name, or inspect it with `fa scenario show <name> --json`",
        )));
    }
    let entry = proposal.clone().seal(Vec::new(), None)?;
    let mut props = vec![
        (
            property::FA_PAYLOAD,
            scalar_bytes("scenario._fa_payload", body_bytes)?,
        ),
        (
            property::FA_DIGEST,
            scalar_bytes("scenario._fa_digest", body.digest()?.to_vec())?,
        ),
        (
            property::BOOK_ID,
            scalar_bytes("book_id", book.book_id.0.to_vec())?,
        ),
        (property::CODE, scalar_text("scenario.code", name)?),
        (property::STATE, ScenarioState::Open.scalar()),
    ];
    props.sort_by_key(|(k, _)| k.0);
    let mut in_case = WriteBatch::new(relation::IN_CASE);
    in_case.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    in_case.create_vertex(scenario, vec![label::SCENARIO], props);
    in_case.add_edge(
        edge_id(relation::IN_CASE, evid, scenario),
        evid,
        scenario,
        vec![],
    );
    txn.write(db, in_case)?;
    finish(db, ctx, book, txn, &proposal, scenario, evid).await
}

/// Admit `capability` to run an intent in a scenario before anything is read
/// for it (doctrine 8): the ScenarioControl Plan op, current at the head and
/// not revoked there. The facade runs this before it materializes the
/// scenario to rehearse the intent; [`plan_into_scenario`] admits again and
/// witnesses revocation inside its transaction.
pub fn admit_scenario_plan<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    capability: &Capability,
) -> Outcome<()> {
    if let Err(r) = admit(db, book, capability, Kind::Plan)? {
        return Ok(Err(r));
    }
    crate::policy::capability_admitted(db, book, capability)
}

/// What a scenario intent's checks found: the recorded outcome of its
/// identical retry, or the open scenario it may be planned into.
enum Checked {
    Recorded(ScenarioRecorded),
    Admitted(ScenarioView),
}

/// Every check a scenario intent meets before anything is read for it,
/// rehearsed or written (doctrine 8), in one place: the facade runs them
/// ([`admit_scenario_intent`]) before it materializes the scenario, and
/// [`plan_into_scenario`] again before it writes. In order: the name; the
/// ScenarioControl Plan op; the intent's holder and coordinates; the
/// planner's authority over the intent itself, admitted as a dry run of it
/// on trunk is (current and not revoked, every leg within its unit's
/// ceiling, the intent within the token's scope caveats); its class; the
/// scenario and its owner; an identical retry, whose recorded outcome stands
/// whatever the scenario's state is now (FA-INV-09); then the scenario's
/// state, start date and intent cap.
fn check_plan<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    name: &str,
    intent: &PostIntent,
    capability: &Capability,
) -> Outcome<Checked> {
    if let Err(r) = check_name(name) {
        return Ok(Err(r));
    }
    if let Err(r) = admit(db, book, capability, Kind::Plan)? {
        return Ok(Err(r));
    }
    let p = intent.proposal();
    if p.principal_ref != capability.holder() {
        return Ok(Err(denial(&Denial::NotHolder {
            holder: capability.holder(),
            principal: p.principal_ref,
        })));
    }
    if p.book_id != book.book_id || p.branch_id != Id128::TRUNK {
        return Ok(Err(usage(
            "a scenario plans intents for this book's trunk coordinates",
            "plan the intent with this book's id and the trunk branch",
        )));
    }
    let rehearsal = crate::post::PostRequest {
        proposal: p.clone(),
        approvals: intent.approvals().to_vec(),
        capability: capability.clone(),
        plan_certificate: None,
    };
    if let Err(r) =
        crate::post::authorize_request(db, book, &rehearsal, crate::post::Admission::Plan)?
    {
        return Ok(Err(r));
    }
    // A Revision or Restatement is rehearsed in a scenario for its case
    // (plan §8.3); it reaches trunk only in that case's own Post.
    let delta = matches!(
        p.class,
        fa_model::EntryClass::REVISION | fa_model::EntryClass::RESTATEMENT
    );
    if !crate::batch::batchable(p.class) && !delta {
        return Ok(Err(usage(
            format!(
                "a {} entry cannot join a scenario",
                p.class.name().unwrap_or("?")
            ),
            "plan Original, Adjusting, Reversal, Pending or Resolution entries, or a Revision or Restatement case's Revision or Restatement entries",
        )));
    }
    let Some(view) = read_scenario(db, book, name)? else {
        return Ok(Err(unknown(name)));
    };
    if view.body.owner != capability.holder() {
        return Ok(Err(Refusal::new(
            code::CAPABILITY,
            exit::SAFETY,
            format!(
                "scenario `{name}` belongs to principal {:032x}; only its owner plans into it",
                view.body.owner.0
            ),
            "plan §15.2 (a scenario is its owner's counterfactual intent log)",
            "fork your own scenario with `fa scenario fork <name>`",
        )));
    }
    // A recorded identity is this Plan's retry, or another intent under the
    // same key, judged by the kernel's retry law (plan §4.9), never by the
    // record's bytes: a resubmitted intent reseals its text with fresh salts.
    let evid = entry_vid(
        book.book_id,
        &view.body.owner.0.to_le_bytes(),
        &record_key(Kind::Plan, view.body.vid(), &p.idempotency_key),
    );
    if let Some(planned) = view.intents.iter().find(|i| i.record == evid) {
        let same = planned.capability == *capability
            && planned.intent.approvals() == intent.approvals()
            && match (
                planned.intent.proposal().semantic_digest(&book.seal_key),
                p.semantic_digest(&book.seal_key),
            ) {
                (Ok(a), Ok(b)) => a == b,
                _ => planned.intent.proposal().proposal_digest()? == p.proposal_digest()?,
            };
        if !same {
            let row = db.vertex(evid)?.ok_or_else(|| {
                KernelError::Corrupt("a scenario intent's record vanished".into())
            })?;
            return Ok(Err(conflict_with(&row)));
        }
        return Ok(Ok(Checked::Recorded(ScenarioRecorded {
            scenario: view.vid,
            control_entry: evid,
            recorded_at: planned.recorded_at,
            already_recorded: true,
        })));
    }
    if view.state != ScenarioState::Open {
        // Running in a discarded scenario: the fix names a fresh scenario to
        // run in instead (which `fa scenario fork` then opens).
        let mut refusal = not_open(&view.body, view.state);
        if let Some(fresh) = fresh_name(db, book, name)? {
            refusal.fix = format!(
                "open `fa scenario fork {}` and repeat this command with --scenario {fresh}",
                crate::refusal::command_word(&fresh)
            );
            refusal = refusal.or_field_change("scenario", vec![fresh]);
        }
        return Ok(Err(refusal));
    }
    if let Some(from) = view.body.from
        && p.effective_date < from
    {
        return Ok(Err(Refusal::new(
            code::SCENARIO_BEFORE_START,
            exit::REFUSAL,
            format!(
                "the intent is effective {}, before scenario `{name}`'s counterfactual starts on {from}",
                p.effective_date
            ),
            "plan §15.6.5 (a but-for scenario's counterfactual begins at its --from date)",
            "date the intent on or after the scenario's from date, or fork a scenario with an earlier --from",
        )
        .or_field_change("effective_date", vec![from.to_string()])));
    }
    if db.vertex(evid)?.is_some() {
        return Err(KernelError::Corrupt(format!(
            "scenario `{name}` names no Plan record at {:032x}, which is live",
            evid.0
        )));
    }
    if view.intents.len() >= fa_model::limits::MAX_BATCH_ENTRIES {
        return Ok(Err(usage(
            format!(
                "scenario `{name}` already holds {} intents, the most one scenario replays",
                view.intents.len()
            ),
            "fork another scenario for the rest of the counterfactual",
        )));
    }
    Ok(Ok(Checked::Admitted(view)))
}

/// The token only [`materialize_into`] makes: one Plan record of a
/// scenario, posted into the scenario's own scratch replay.
#[derive(Clone, Copy, Debug)]
pub struct Rehearsing(());

/// How [`materialize_into`] numbers the replayed prefix: the protected
/// native coordinates every new materialization uses, or an older v1
/// scenario certificate's compressed ones (that certificate's replay
/// only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coordinates {
    Protected,
    LegacyV1,
}

/// Why [`materialize_into`] stopped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MaterializeRefusal {
    /// The replay of the trunk prefix was refused.
    Replay(Refusal),
    /// The request at this index (from 0) was refused.
    Intent(usize, Refusal),
}

/// A materialized scenario: the target, the replay's map, and the entry
/// each request posted, in order.
pub type Materialized = (Database<fgdb::MemVfs>, crate::scratch::SeqMap, Vec<VId>);

/// A scenario's materialization (plan §15.2): `target`, an empty memory
/// database, receives the source's accounting objects as known at
/// `fork_at`, then each of `requests` in order through every posting law.
/// A case-bound class (PriorPeriodAdjustment, Revision) is rehearsed
/// under [`Rehearsing`], which only this function makes: the period law
/// and the planner's authority hold, the class's case and that case's
/// approvals are not required, and nothing reaches the source.
pub async fn materialize_into<V: asupersync::fs::Vfs + Clone>(
    source: &mut Database<V>,
    mut target: Database<fgdb::MemVfs>,
    ctx: &PurposeContexts,
    book: &BookContext,
    fork_at: CommitSeq,
    coordinates: Coordinates,
    requests: Vec<crate::post::PostRequest>,
) -> Result<Result<Materialized, MaterializeRefusal>, KernelError> {
    if target.frontier()? != CommitSeq(0) || !target.vertices_at(CommitSeq(0))?.is_empty() {
        return Ok(Err(MaterializeRefusal::Replay(usage(
            "a scenario materializes into an empty memory database at sequence zero",
            "create a fresh open_memory database for the materialization",
        ))));
    }
    let replayed = match coordinates {
        Coordinates::Protected => {
            crate::scratch::replay_into(source, &mut target, ctx, book, Some(fork_at)).await?
        }
        Coordinates::LegacyV1 => {
            crate::scratch::replay_into_legacy_scenario_v1(
                source,
                &mut target,
                ctx,
                book,
                Some(fork_at),
            )
            .await?
        }
    };
    let map = match replayed {
        Ok(map) => map,
        Err(refusal) => return Ok(Err(MaterializeRefusal::Replay(refusal))),
    };
    let mut entries = Vec::with_capacity(requests.len());
    for (i, req) in requests.into_iter().enumerate() {
        let admission = if crate::case::case_bound(req.proposal.class) {
            crate::post::Admission::ScratchScenario(Rehearsing(()))
        } else {
            crate::post::Admission::Commit
        };
        match crate::post::post_admitted(&mut target, ctx, book, req, admission).await? {
            Ok(posted) => entries.push(posted.entry_ref().vid),
            Err(refusal) => return Ok(Err(MaterializeRefusal::Intent(i, refusal))),
        }
    }
    Ok(Ok((target, map, entries)))
}

/// Admit `intent` into the scenario `name` before anything is rehearsed for
/// it: every check of [`plan_into_scenario`] but the write. `Some` is the
/// recorded outcome of an identical retry, which needs no rehearsal.
pub fn admit_scenario_intent<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    name: &str,
    intent: &PostIntent,
    capability: &Capability,
) -> Outcome<Option<ScenarioRecorded>> {
    Ok(
        check_plan(db, book, name, intent, capability)?.map(|checked| match checked {
            Checked::Recorded(recorded) => Some(recorded),
            Checked::Admitted(_) => None,
        }),
    )
}

/// Journal `intent` into the open scenario `name` as one Plan record. Only
/// the scenario's owner plans into it; the intent is the owner's, for this
/// book's trunk, of a batchable class, effective on or after the scenario's
/// start date, under a key no other intent in the scenario holds. The
/// caller rehearses it on the scenario's materialization first; the kernel
/// never posts it.
pub async fn plan_into_scenario<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    name: &str,
    intent: PostIntent,
    req: ScenarioRequest,
) -> Outcome<ScenarioRecorded> {
    let view = match check_plan(db, book, name, &intent, &req.capability)? {
        Err(refusal) => return Ok(Err(refusal)),
        Ok(Checked::Recorded(recorded)) => return Ok(Ok(recorded)),
        Ok(Checked::Admitted(view)) => view,
    };
    let p = intent.proposal();
    let extension = intent_bytes(&intent, &req.capability)?;
    let proposal = record_proposal(
        book,
        &view.body,
        Kind::Plan,
        view.body.owner,
        &p.idempotency_key,
        &req,
        Vec::new(),
        vec![(fa_model::entry::SCENARIO_INTENT_EXTENSION, extension)],
    )?;
    if proposal.validate().is_err() {
        return Ok(Err(usage(
            "the Plan record is not a valid ScenarioControl entry",
            "run the intent with `fa scenario run <name> --intent <file>`",
        )));
    }
    let scenario = view.vid;
    let evid = record_vid(book, &proposal);
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
    in_case.add_edge(
        edge_id(relation::IN_CASE, evid, scenario),
        evid,
        scenario,
        vec![],
    );
    txn.write(db, in_case)?;
    finish(db, ctx, book, txn, &proposal, scenario, evid).await
}

/// Discard the open scenario `name`: its owner, or a reviewer holding
/// `approve`, closes it. Nothing is deleted.
pub async fn discard_scenario<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    name: &str,
    req: ScenarioRequest,
) -> Outcome<ScenarioRecorded> {
    if let Err(r) = check_name(name) {
        return Ok(Err(r));
    }
    if let Err(r) = admit(db, book, &req.capability, Kind::Discard)? {
        return Ok(Err(r));
    }
    let Some(view) = read_scenario(db, book, name)? else {
        return Ok(Err(unknown(name)));
    };
    if view.body.owner != req.capability.holder() && !req.capability.holds(Op::Approve) {
        return Ok(Err(denial(&Denial::MissingOp {
            op: Op::Approve,
            what: format!("discarding scenario `{name}`, which another principal owns"),
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
    let scenario = view.vid;
    let evid = record_vid(book, &proposal);
    if let Some(row) = db.vertex(evid)? {
        return Ok(
            recorded_or_conflict(book, &row, &proposal)?.map(|recorded_at| ScenarioRecorded {
                scenario,
                control_entry: evid,
                recorded_at,
                already_recorded: true,
            }),
        );
    }
    if view.state != ScenarioState::Open {
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
        scenario,
        property::STATE,
        Some(ScenarioState::Open.scalar()),
        ScenarioState::Discarded.scalar(),
        WriteMismatchPolicy::AbortWrite,
    );
    in_case.add_edge(
        edge_id(relation::IN_CASE, evid, scenario),
        evid,
        scenario,
        vec![],
    );
    txn.write(db, in_case)?;
    finish(db, ctx, book, txn, &proposal, scenario, evid).await
}

/// The scenario `name` as its records state it at the head.
pub fn read_scenario<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    name: &str,
) -> Result<Option<ScenarioView>, KernelError> {
    let vid = scenario_vid(book.book_id, name);
    match db.vertex(vid)? {
        Some(row) if row.labels.contains(&label::SCENARIO) => Ok(Some(view_of(db, &row)?)),
        Some(_) => Err(KernelError::Corrupt(format!(
            "scenario identity {:032x} holds a vertex that is not a Scenario",
            vid.0
        ))),
        None => Ok(None),
    }
}

/// Every scenario of the book, in the order they were forked (their Open
/// records).
pub fn list_scenarios<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
) -> Result<Vec<ScenarioView>, KernelError> {
    let mut out = Vec::new();
    for row in db.vertices()? {
        if row.labels.contains(&label::SCENARIO) {
            let view = view_of(db, &row)?;
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
    row: &VertexRow,
) -> Result<ScenarioView, KernelError> {
    let scenario = row.vid;
    let body = scenario_row_body(row)?;
    let state = ScenarioState::from_scalar(prop(row, property::STATE)).ok_or_else(|| {
        KernelError::Corrupt(format!("scenario {:032x} state mirror", scenario.0))
    })?;
    let seq = db.frontier()?;
    let mut intents = Vec::new();
    let mut assumptions = None;
    let mut opened_at = None;
    let mut discarded = None;
    for edge in db.edges_at(seq)? {
        let e = &edge.entry;
        if e.dst != scenario
            || e.relation != relation::IN_CASE
            || e.eid != edge_id(relation::IN_CASE, e.src, scenario)
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
        if entry.proposal.class != EntryClass::SCENARIO_CONTROL {
            return Err(KernelError::Corrupt(format!(
                "scenario {:032x} has a member {:032x} that is not a ScenarioControl record",
                scenario.0, e.src.0
            )));
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
                "scenario record {:032x} carries no LifecycleTransition",
                e.src.0
            )));
        };
        if *object_ref != scenario {
            continue;
        }
        let open = ScenarioState::Open.tag();
        match (*from, *to) {
            (0, t) if t == open => {
                let mut oids = Vec::with_capacity(proof_refs.len());
                for r in proof_refs {
                    let TypedRef::Object(oid) = r else {
                        return Err(KernelError::Corrupt(format!(
                            "scenario Open record {:032x} names a proof that is not a document",
                            e.src.0
                        )));
                    };
                    oids.push(*oid);
                }
                assumptions = Some(oids);
                opened_at = Some(recorded_at);
            }
            (f, t) if f == open && t == open => {
                let Some((_, ext)) = entry
                    .proposal
                    .extensions
                    .iter()
                    .find(|(tag, _)| *tag == fa_model::entry::SCENARIO_INTENT_EXTENSION)
                else {
                    return Err(KernelError::Corrupt(format!(
                        "scenario Plan record {:032x} carries no intent",
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
            (f, t) if f == open && t == ScenarioState::Discarded.tag() => {
                discarded = Some(ScenarioClosure {
                    record: e.src,
                    recorded_at,
                    by: entry.proposal.principal_ref,
                });
            }
            _ => {
                return Err(KernelError::Corrupt(format!(
                    "scenario record {:032x} names transition {from} -> {to}",
                    e.src.0
                )));
            }
        }
    }
    let (Some(assumptions), Some(opened_at)) = (assumptions, opened_at) else {
        return Err(KernelError::Corrupt(format!(
            "scenario {:032x} has no Open record",
            scenario.0
        )));
    };
    intents.sort_by_key(|i| (i.recorded_at, i.record.0));
    Ok(ScenarioView {
        vid: scenario,
        body,
        state,
        opened_at,
        assumptions,
        intents,
        discarded,
    })
}

// ---------------------------------------------------------------------------
// The receivership (plan §15.6 "The trustee or receiver takes over")
// ---------------------------------------------------------------------------

/// The receivership branch's name (`fa book fork receivership`).
pub const RECEIVERSHIP: &str = "receivership";
/// The idempotency key of the receivership's book-scope hold (one per
/// principal and book: a retry is the recorded hold).
pub const RECEIVERSHIP_HOLD_KEY: &[u8] = b"fa:receivership-hold";

/// The receiver's fork, as recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivershipForked {
    /// The appointment sequence: the trunk prefix the hold pins and the
    /// branch replays.
    pub appointment: CommitSeq,
    /// The book-scope hold over the pre-appointment trunk.
    pub hold: crate::legal_hold::LegalHoldPlaced,
    /// The `receivership` scenario's Open record.
    pub branch: ScenarioRecorded,
}

/// The appointment an earlier fork recorded: the branch's fork sequence,
/// else the principal's receivership hold's; `None` before either exists.
fn recorded_appointment<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    principal: VId,
) -> Result<Option<CommitSeq>, KernelError> {
    if let Some(branch) = read_scenario(db, book, RECEIVERSHIP)? {
        return Ok(Some(branch.body.fork_at));
    }
    let hold = entry_vid(
        book.book_id,
        &principal.0.to_le_bytes(),
        RECEIVERSHIP_HOLD_KEY,
    );
    if let Some(crate::legal_hold::LegalHold {
        through: Some(through),
        ..
    }) = crate::legal_hold::read_legal_hold(db, book.book_id, hold)?
    {
        return Ok(Some(through));
    }
    Ok(None)
}

/// Fork the receivership (plan §15.6; fa-k07b). Refused before anything is
/// read unless the capability holds `receivership` and the ops of both
/// records it writes (the HoldControl Place row's `hold`, the
/// ScenarioControl Open row's `post`). Then, on the appointing order's
/// authority:
///
/// 1. a book-scope legal hold over everything recorded through the
///    appointment sequence: the pre-appointment trunk is pinned against
///    erasure, garbage collection and retention expiry;
/// 2. the `receivership` scenario forked at that same sequence, the order as
///    its assumption document: the estate posts there (`--scenario
///    receivership`) and reads it (`--branch scenario:receivership`) until
///    substrate branches land (Appendix H R-BR).
///
/// Two commits, each idempotent under its own identity, so a retry after a
/// failure between them completes the fork. `at: None` is the head, or the
/// appointment already recorded by an earlier attempt. A different
/// appointment than the recorded one is refused: a book has one
/// receivership.
pub async fn fork_receivership<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    authority: Oid,
    at: Option<CommitSeq>,
    hold_description: Erasable<String>,
    req: ScenarioRequest,
) -> Outcome<ReceivershipForked> {
    let capability = req.capability.clone();
    let holder = capability.holder();
    if let Err(d) = fa_policy::admit(
        &capability,
        &Intent {
            principal: holder,
            trunk: true,
            op: Op::Receivership,
            book: book.book_id,
            legs: &[],
        },
    ) {
        return Ok(Err(denial(&d)));
    }
    if let Err(r) = crate::legal_hold::admit(db, book, &capability, holder, "Place")? {
        return Ok(Err(r));
    }
    if let Err(r) = admit(db, book, &capability, Kind::Open)? {
        return Ok(Err(r));
    }
    // What the Open below would refuse is refused before the hold is
    // written, so a refused fork leaves nothing behind: a `receivership`
    // scenario another principal opened, or one already discarded.
    if let Some(existing) = read_scenario(db, book, RECEIVERSHIP)? {
        if existing.state != ScenarioState::Open {
            return Ok(Err(not_open(&existing.body, existing.state)));
        }
        if existing.body.owner != holder {
            return Ok(Err(Refusal::new(
                code::IDEMPOTENCY_CONFLICT,
                exit::CONFLICT,
                format!(
                    "this book's receivership was forked by principal {:032x}; a book has one receivership",
                    existing.body.owner.0
                ),
                "plan §15.6 (the receivership is one branch at the appointment)",
                format!("inspect it with `fa scenario show {RECEIVERSHIP} --json`"),
            )));
        }
    }
    let appointment = match (at, recorded_appointment(db, book, holder)?) {
        (Some(at), Some(recorded)) if at != recorded => {
            return Ok(Err(Refusal::new(
                code::IDEMPOTENCY_CONFLICT,
                exit::CONFLICT,
                format!(
                    "this book's receivership was forked at sequence {}, not {}; a book has one receivership",
                    recorded.0, at.0
                ),
                "plan §15.6 (the receivership is one branch at the appointment)",
                format!(
                    "inspect it with `fa scenario show {RECEIVERSHIP} --json`, or repeat the fork without --at (or with --at {})",
                    recorded.0
                ),
            )));
        }
        (Some(at), _) => at,
        (None, Some(recorded)) => recorded,
        (None, None) => db.frontier()?,
    };
    let hold = match crate::legal_hold::place_legal_hold(
        db,
        ctx,
        book,
        &capability,
        crate::legal_hold::LegalHoldRequest {
            principal: holder,
            reach: crate::legal_hold::HoldReach::Through(appointment),
            authority,
            effective_date: req.effective_date,
            idempotency_key: RECEIVERSHIP_HOLD_KEY.to_vec(),
            description: hold_description,
        },
    )
    .await?
    {
        Ok(hold) => hold,
        Err(r) => return Ok(Err(r)),
    };
    let fork = ScenarioFork {
        at: Some(appointment),
        from: None,
        assumptions: vec![authority],
    };
    let branch = match open_scenario(db, ctx, book, RECEIVERSHIP, fork, req).await? {
        Ok(branch) => branch,
        Err(r) => return Ok(Err(r)),
    };
    Ok(Ok(ReceivershipForked {
        appointment,
        hold,
        branch,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body() -> ScenarioBody {
        ScenarioBody {
            book_id: Id128([7; 16]),
            name: "but-for-breach".into(),
            owner: VId(42),
            fork_at: CommitSeq(9),
            from: Some(DateDay(20_513)),
        }
    }

    #[test]
    fn scenario_bodies_round_trip_and_bind_every_field() {
        for b in [
            body(),
            ScenarioBody {
                from: None,
                ..body()
            },
        ] {
            let bytes = b.canonical_bytes().unwrap();
            assert_eq!(ScenarioBody::decode(&bytes).unwrap(), b);
            for end in 0..bytes.len() {
                assert!(ScenarioBody::decode(&bytes[..end]).is_err(), "prefix {end}");
            }
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!(ScenarioBody::decode(&trailing).is_err());
        }
        let b = body();
        for changed in [
            ScenarioBody {
                name: "pro-forma".into(),
                ..b.clone()
            },
            ScenarioBody {
                owner: VId(43),
                ..b.clone()
            },
            ScenarioBody {
                fork_at: CommitSeq(10),
                ..b.clone()
            },
            ScenarioBody {
                from: Some(DateDay(20_514)),
                ..b.clone()
            },
            ScenarioBody {
                from: None,
                ..b.clone()
            },
        ] {
            assert_ne!(changed.digest().unwrap(), b.digest().unwrap());
        }
        let renamed = ScenarioBody {
            name: "pro-forma".into(),
            ..b.clone()
        };
        assert_ne!(renamed.vid(), b.vid());
        let refork = ScenarioBody {
            fork_at: CommitSeq(10),
            ..b.clone()
        };
        assert_eq!(refork.vid(), b.vid(), "one scenario per name in a book");
        assert_ne!(
            b.vid(),
            fa_model::draft_vid(b.book_id, &b.name),
            "a scenario and a draft of one name are distinct objects"
        );
    }

    #[test]
    fn a_has_from_flag_other_than_zero_or_one_is_refused() {
        let mut bytes = ScenarioBody {
            from: None,
            ..body()
        }
        .canonical_bytes()
        .unwrap();
        let last = bytes.len() - 1;
        bytes[last] = 2;
        assert!(ScenarioBody::decode(&bytes).is_err());
    }

    #[test]
    fn record_keys_separate_kinds_scenarios_and_intents_within_the_key_bound() {
        let a = VId(1);
        let b = VId(2);
        let keys = [
            record_key(Kind::Open, a, &[]),
            record_key(Kind::Plan, a, b"k1"),
            record_key(Kind::Plan, a, b"k2"),
            record_key(Kind::Plan, b, b"k1"),
            record_key(Kind::Discard, a, &[]),
        ];
        for (i, k) in keys.iter().enumerate() {
            assert!(k.len() <= fa_model::limits::MAX_IDEMPOTENCY_KEY_BYTES);
            for other in &keys[i + 1..] {
                assert_ne!(k, other);
            }
        }
    }

    #[test]
    fn scenario_states_round_trip_through_their_scalars() {
        for s in [ScenarioState::Open, ScenarioState::Discarded] {
            assert_eq!(ScenarioState::from_scalar(Some(&s.scalar())), Some(s));
        }
        for bad in [0, 3] {
            assert_eq!(
                ScenarioState::from_scalar(Some(&CanonicalScalar::Int(bad))),
                None
            );
        }
        assert_eq!(ScenarioState::from_scalar(None), None);
    }
}
