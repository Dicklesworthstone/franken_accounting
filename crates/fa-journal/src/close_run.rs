//! A bounded, durable close workflow over reviewed native effects (plan §7.5).
//!
//! The declaration is immutable. A task's receipt is staged in the native
//! promotion/period transaction, so recovery can never observe a completed
//! task without its effect, or an effect acknowledged by this run without its
//! receipt. A refusal leaves the task ready for a later admissible attempt.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_model::symbols::{label, property, relation};
use fa_model::{
    ApprovalRef, CloseRunBody, CloseTaskBody, CloseTaskBodyAction, ControlKind, ControlPayload,
    EntryClass, EntryOrigin, EntryPayload, EntryRef, Erasable, Id128, Oid, Reader, TypedRef,
    Writer, close_run_vid, close_task_vid, domain_digest, entry_mirrors, entry_vid, period_vid,
    report_certificate_vid,
};
use fa_policy::{Capability, Intent, Op};
use fa_time::{DateDay, PeriodTransition};
use fgdb::{Database, VertexRow, WriteBatch, WriteMismatchPolicy, WriteTxn, WriteTxnError};
use fgdb_delta_types::{DeltaRow, ElementId};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::batch::TemplateByteTracker;
use crate::draft::{DraftRehearsalRequest, DraftRehearsalSource, DraftRequest};
use crate::period::TransitionPlan;
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{PeriodRow, bytes, edge_id, prop, scalar_bytes, scalar_text};
use crate::{BookContext, policy};

pub const MAX_TASKS: usize = fa_model::limits::MAX_CLOSE_RUN_TASKS;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloseTaskDefinition {
    pub id: String,
    pub depends_on: Vec<String>,
    pub action: CloseTaskAction,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CloseTaskAction {
    PromoteDraft {
        source: DraftRehearsalSource,
        certificate_digest: [u8; 32],
        expected_entries: Vec<EntryRef>,
    },
    PeriodTransition(PeriodTransition),
    /// Future task kinds are explicitly refused, never marked complete.
    Unsupported(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloseRunDefinition {
    pub name: String,
    pub period: String,
    pub tasks: Vec<CloseTaskDefinition>,
}

#[derive(Clone, Debug)]
pub struct CloseTaskRequest {
    pub capability: Capability,
    pub description: Erasable<String>,
    pub transition_plan: Option<TransitionPlan>,
    pub approvals: Vec<ApprovalRef>,
    /// Selected combined review, checked at the current native frontier.
    /// Its container identity is not a semantic replay verdict: the facade
    /// replays the complete retained certificate before supplying this value.
    pub review: Option<CloseTaskReview>,
}

/// Bounded identity binding of the existing combined-rehearsal certificate.
/// The fields cannot be replaced independently of its canonical content digest.
/// This checks its family and graph identity, not its accounting computation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloseTaskReview {
    certificate: [u8; 32],
    book: Id128,
    run: VId,
    body_digest: [u8; 32],
    opened_at: CommitSeq,
    checked_at: CommitSeq,
}

impl CloseTaskReview {
    pub fn from_certificate(bytes: &[u8], checked_at: CommitSeq) -> Result<Self, Refusal> {
        const MAX_BYTES: usize = 64 * 1024 * 1024;
        let malformed = |error: fa_model::DecodeError| {
            invalid(format!("malformed combined close review: {error}"))
        };
        if !(32..=MAX_BYTES).contains(&bytes.len()) {
            return Err(invalid("the combined close review exceeds its byte bound"));
        }
        let mut r = Reader::new(bytes);
        if r.bytes(64, "close review format").map_err(malformed)?
            != b"fa:close-run-rehearsal-certificate:v1"
        {
            return Err(invalid(
                "the selected artifact is not a combined close review",
            ));
        }
        // The facade checks the native baseline and each original draft
        // certificate. Borrow their bounded frames here; do not reimplement
        // report semantics or allocate copies inside the posting kernel.
        r.bytes(MAX_BYTES, "close review baseline")
            .map_err(malformed)?;
        let body = CloseRunBody::decode(
            r.bytes(fa_model::limits::MAX_CLOSE_RUN_BYTES, "close review graph")
                .map_err(malformed)?,
        )
        .map_err(malformed)?;
        let opened_at = CommitSeq(r.u64("close review opened at").map_err(malformed)?);
        let count = r.u32("close review drafts").map_err(malformed)? as usize;
        let expected = body
            .tasks
            .iter()
            .filter(|task| matches!(task.action, CloseTaskBodyAction::PromoteDraft { .. }))
            .count();
        if count != expected {
            return Err(invalid(
                "the combined review omits or adds original draft reviews",
            ));
        }
        for _ in 0..count {
            r.bytes(MAX_BYTES, "close review draft")
                .map_err(malformed)?;
        }
        r.u128("close review producer").map_err(malformed)?;
        r.fixed::<32>("close review capability")
            .map_err(malformed)?;
        r.bytes(MAX_BYTES, "close review output")
            .map_err(malformed)?;
        let certificate = r.fixed("close review digest").map_err(malformed)?;
        r.finish().map_err(malformed)?;
        if opened_at.0 == 0
            || opened_at > checked_at
            || domain_digest(
                b"fa:close-run-rehearsal-certificate-digest:v1",
                &[&bytes[..bytes.len() - 32]],
            ) != certificate
        {
            return Err(invalid(
                "the combined close review has an invalid identity or digest",
            ));
        }
        Ok(Self {
            certificate,
            book: body.book_id,
            run: close_run_vid(body.book_id, &body.name),
            body_digest: body.digest().map_err(|error| invalid(error.to_string()))?,
            opened_at,
            checked_at,
        })
    }

    /// Rebind only the execution frontier while one owned facade invocation
    /// advances its already-rehearsed tasks. This grants no authority and does
    /// not stand in for the facade's full replay/current-result comparison.
    pub fn at_frontier(&self, checked_at: CommitSeq) -> Self {
        Self {
            checked_at,
            ..self.clone()
        }
    }
}

/// The original selection of one complete combined review. It is published
/// atomically with its first native task, never merely on an attempted run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloseRunReviewReceipt {
    pub record: VId,
    pub certificate: [u8; 32],
    pub recorded_at: CommitSeq,
    pub principal: VId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloseTaskReceipt {
    pub record: VId,
    pub effect: VId,
    pub recorded_at: CommitSeq,
    pub principal: VId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloseTaskView {
    pub vid: VId,
    pub id: String,
    pub ready: bool,
    pub completion: Option<CloseTaskReceipt>,
    /// The combined review named by this completion; None for legacy tasks.
    pub rehearsal: Option<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloseRunView {
    pub vid: VId,
    pub body: CloseRunBody,
    pub opened_at: CommitSeq,
    pub complete: bool,
    pub tasks: Vec<CloseTaskView>,
    /// Append-only selections in native publication order. The last is the
    /// current binding; replacing it never rewrites earlier task evidence.
    pub reviews: Vec<CloseRunReviewReceipt>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloseTaskRecorded {
    pub run: CloseRunView,
    pub task: String,
    pub receipt: CloseTaskReceipt,
    pub already_recorded: bool,
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::STRUCTURE,
        exit::USAGE,
        message,
        "plan §7.5 (immutable reviewed close tasks and atomic completion)",
        "inspect the run and retain a fresh complete draft review before starting a new run",
    )
}

fn conflict(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::IDEMPOTENCY_CONFLICT,
        exit::CONFLICT,
        message,
        "plan §7.5 (one immutable close run per name)",
        "resume the existing run, or choose a new name for different reviewed work",
    )
}

fn review_invalidated(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::PLAN_INVALIDATED,
        exit::CONFLICT,
        message,
        "plan §7.5 (a selected combined close review cannot be silently dropped or substituted)",
        "retain a fresh `fa close dry-run --run <name> --certify` result and select its full digest with `close run|step --rehearsal C:<digest>`",
    )
}

fn corrupt(message: impl Into<String>) -> KernelError {
    KernelError::Corrupt(format!("close run: {}", message.into()))
}

fn encode(error: fa_model::EncodeError) -> KernelError {
    KernelError::Model(error.into())
}

fn admit<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    capability: &Capability,
    transition: Option<&str>,
) -> Outcome<()> {
    let op = transition
        .map(|transition| {
            policy::steward()?
                .transition_op("CloseControl", transition)
                .ok_or_else(|| {
                    corrupt(format!(
                        "no registered CloseControl {transition} authority rule"
                    ))
                })
        })
        .transpose()?;
    let permission = fa_policy::admit_read(capability, capability.holder(), book.book_id)
        .and_then(|()| fa_policy::reach(capability, &fa_policy::Reach::whole_book(true), None))
        .and_then(|()| {
            if let Some(op) = op {
                fa_policy::admit(
                    capability,
                    &Intent {
                        principal: capability.holder(),
                        trunk: true,
                        op,
                        book: book.book_id,
                        legs: &[],
                    },
                )
            } else {
                Ok(())
            }
        });
    if let Err(denial) = permission {
        return Ok(Err(policy::refusal(&denial)));
    }
    policy::current_at(db, book, capability).map(|result| result.map(|_| ()))
}

fn entries_digest(entries: &[EntryRef]) -> Result<[u8; 32], KernelError> {
    let mut w = Writer::new();
    w.list(entries, |w, entry| entry.encode(w));
    Ok(domain_digest(
        b"fa:close-task-entries:v1",
        &[&w.finish().map_err(encode)?],
    ))
}

fn target(transition: PeriodTransition) -> Result<u8, Refusal> {
    match transition {
        PeriodTransition::SoftClose => Ok(2),
        PeriodTransition::Close => Ok(3),
        PeriodTransition::Lock => Ok(4),
        _ => Err(invalid(
            "a close run supports only SoftClose, Close or Lock as its final period task",
        )),
    }
}

fn transition(to: u8) -> Result<PeriodTransition, KernelError> {
    match to {
        2 => Ok(PeriodTransition::SoftClose),
        3 => Ok(PeriodTransition::Close),
        4 => Ok(PeriodTransition::Lock),
        _ => Err(corrupt("unsupported period target in a recorded task")),
    }
}

fn definition_body(
    book: &BookContext,
    definition: &CloseRunDefinition,
    owner: VId,
) -> Outcome<CloseRunBody> {
    if definition.tasks.is_empty() || definition.tasks.len() > MAX_TASKS {
        return Ok(Err(invalid(format!(
            "a close run needs 1..={MAX_TASKS} tasks"
        ))));
    }
    let mut tasks = Vec::with_capacity(definition.tasks.len());
    let mut drafts = BTreeSet::new();
    for task in &definition.tasks {
        let action = match &task.action {
            CloseTaskAction::Unsupported(kind) => {
                return Ok(Err(invalid(format!(
                    "close task kind `{kind}` has no native execution path"
                ))));
            }
            CloseTaskAction::PeriodTransition(t) => {
                let to = match target(*t) {
                    Ok(to) => to,
                    Err(refusal) => return Ok(Err(refusal)),
                };
                CloseTaskBodyAction::PeriodTransition { to }
            }
            CloseTaskAction::PromoteDraft {
                source,
                certificate_digest,
                expected_entries,
            } => {
                if source.body.book_id != book.book_id || !drafts.insert(source.body.vid()) {
                    return Ok(Err(invalid(
                        "a draft must belong to this book and occur only once in a close run",
                    )));
                }
                if expected_entries.is_empty()
                    || expected_entries.len() > fa_model::limits::MAX_BATCH_ENTRIES
                    || expected_entries
                        .iter()
                        .map(|entry| entry.vid)
                        .collect::<BTreeSet<_>>()
                        .len()
                        != expected_entries.len()
                {
                    return Ok(Err(invalid(
                        "a draft task requires a bounded, distinct, complete reviewed entry list",
                    )));
                }
                CloseTaskBodyAction::PromoteDraft {
                    draft: source.body.vid(),
                    name: source.body.name.clone(),
                    owner: source.body.owner,
                    source_known_at: source.known_at,
                    source_digest: source.digest()?,
                    certificate_digest: *certificate_digest,
                    entries_digest: entries_digest(expected_entries)?,
                    entry_count: expected_entries.len() as u32,
                }
            }
        };
        let mut depends_on = task.depends_on.clone();
        depends_on.sort();
        tasks.push(CloseTaskBody {
            id: task.id.clone(),
            depends_on,
            action,
        });
    }
    tasks.sort_by(|a, b| a.id.cmp(&b.id));
    let body = CloseRunBody {
        book_id: book.book_id,
        name: definition.name.clone(),
        period: definition.period.clone(),
        owner,
        tasks,
    };
    if let Err(error) = body.validate() {
        return Ok(Err(invalid(format!("invalid close graph: {error}"))));
    }
    let finals: Vec<_> = body
        .tasks
        .iter()
        .filter(|task| matches!(task.action, CloseTaskBodyAction::PeriodTransition { .. }))
        .collect();
    if finals.len() > 1 {
        return Ok(Err(invalid(
            "a close run has at most one final period transition",
        )));
    }
    if let Some(final_task) = finals.first() {
        let mut ancestors = BTreeSet::new();
        let mut pending = final_task.depends_on.clone();
        while let Some(id) = pending.pop() {
            if ancestors.insert(id.clone()) {
                let task = body
                    .tasks
                    .iter()
                    .find(|task| task.id == id)
                    .ok_or_else(|| corrupt("validated dependency is absent"))?;
                pending.extend(task.depends_on.iter().cloned());
            }
        }
        if ancestors.len() + 1 != body.tasks.len() {
            return Ok(Err(invalid(
                "the final period transition must depend on every other close task",
            )));
        }
    }
    Ok(Ok(body))
}

/// This primitive verifies retention identity, not the certificate's report
/// semantics. The facade independently replays DraftDiff before calling us;
/// the kernel also binds native source history and the actual staged effects.
fn certificate_row(row: &VertexRow, book: &BookContext, digest: &[u8; 32]) -> bool {
    row.vid == report_certificate_vid(book.book_id, digest)
        && row.labels.as_slice() == [label::CERTIFICATE]
        && row.retired_at.is_none()
        && row.props.len() == 3
        && matches!(prop(row, property::BOOK_ID), Some(CanonicalScalar::Bytes(value)) if value.as_slice() == book.book_id.0)
        && matches!(prop(row, property::FA_DIGEST), Some(CanonicalScalar::Bytes(value)) if value.as_slice() == digest)
        && matches!(
            prop(row, property::FA_PAYLOAD),
            Some(CanonicalScalar::Bytes(_))
        )
}

fn validate_draft<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    period: &str,
    task: &CloseTaskBody,
) -> Outcome<()> {
    let CloseTaskBodyAction::PromoteDraft {
        draft,
        name,
        owner,
        source_known_at,
        source_digest,
        certificate_digest,
        entry_count,
        ..
    } = &task.action
    else {
        return Ok(Ok(()));
    };
    let retained = db.vertex(report_certificate_vid(book.book_id, certificate_digest))?;
    if retained
        .as_ref()
        .is_none_or(|row| !certificate_row(row, book, certificate_digest))
    {
        return Ok(Err(invalid(
            "the exact reviewed draft certificate is not retained in this book",
        )));
    }
    let original = match crate::draft::capture_close_source(
        db,
        cx,
        book,
        &DraftRehearsalRequest {
            name: name.clone(),
            known_at: *source_known_at,
        },
    )? {
        Ok((source, _)) => source,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if original.body.vid() != *draft
        || original.body.owner != *owner
        || original.digest()? != *source_digest
    {
        return Ok(Err(invalid(
            "the draft task does not bind its complete original native source",
        )));
    }
    let (mut current, view) = match crate::draft::capture_close_source(
        db,
        cx,
        book,
        &DraftRehearsalRequest {
            name: name.clone(),
            known_at: db.frontier()?,
        },
    )? {
        Ok(source) => source,
        Err(refusal) => return Ok(Err(refusal)),
    };
    current.known_at = *source_known_at;
    if current != original || view.intents.len() != *entry_count as usize {
        return Ok(Err(invalid(
            "the draft's membership changed after its bound close review",
        )));
    }
    let period_row = db
        .vertex(period_vid(&book.calendar.id, period))?
        .ok_or_else(|| corrupt("the close run names a missing period"))?;
    let selected = PeriodRow::decode(&period_row)?;
    for planned in &view.intents {
        let proposal = planned
            .resolved_entry
            .as_ref()
            .map_or_else(|| planned.intent.proposal(), |entry| &entry.proposal);
        // The native discriminator law distinguishes overlapping Normal and
        // special periods; a shared civil date alone never selects a special.
        let fiscal_year = book.calendar.fiscal_year_of(proposal.effective_date)?;
        let periods = book.calendar.periods_for_year(fiscal_year)?;
        let resolved = fa_time::resolve_period(
            &periods,
            proposal.effective_date,
            proposal
                .effective_period
                .as_ref()
                .map(|period| period.code.as_str()),
        );
        if proposal
            .effective_period
            .as_ref()
            .is_some_and(|p| p.calendar != book.calendar.id || p.code != period)
            || proposal.effective_date < selected.start
            || proposal.effective_date >= selected.end
            || !resolved.is_ok_and(|resolved| resolved.code == period)
        {
            return Ok(Err(invalid(
                "every promoted draft member must affect the run's selected period",
            )));
        }
    }
    Ok(Ok(()))
}

#[derive(Clone, Copy)]
enum RecordKind {
    Open,
    Task,
    Complete,
    Review,
}

impl RecordKind {
    fn tag(self) -> u8 {
        match self {
            Self::Open => 0,
            Self::Task => 1,
            Self::Complete => 2,
            Self::Review => 3,
        }
    }
    fn states(self) -> (u8, u8) {
        match self {
            Self::Open | Self::Task => (0, 1),
            Self::Complete => (1, 2),
            Self::Review => (1, 1),
        }
    }
}

fn review_key(run: VId, certificate: &[u8; 32]) -> Vec<u8> {
    domain_digest(
        b"fa:close-review-key:v1",
        &[&run.0.to_le_bytes(), certificate],
    )
    .to_vec()
}

fn record_key(kind: RecordKind, object: VId) -> Vec<u8> {
    domain_digest(
        b"fa:close-record-key:v1",
        &[&[kind.tag()], &object.0.to_le_bytes()],
    )
    .to_vec()
}

fn proposal(
    book: &BookContext,
    body: &CloseRunBody,
    kind: RecordKind,
    object: VId,
    principal: VId,
    description: Erasable<String>,
    effect: Option<VId>,
) -> Result<EntryPayload, KernelError> {
    let (from, to) = kind.states();
    Ok(EntryPayload {
        schema_minor: fa_model::entry::SCHEMA_MINOR,
        book_id: book.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::CLOSE_CONTROL,
        effective_date: DateDay(0),
        document_date: None,
        description,
        effective_period: None,
        legs: Vec::new(),
        control: Some(ControlPayload::LifecycleTransition {
            object_ref: object,
            from,
            to,
            proof_refs: effect.into_iter().map(TypedRef::Vertex).collect(),
            reason_code: 0,
        }),
        unit_totals: Vec::new(),
        base_totals: None,
        idempotency_key: record_key(kind, object),
        origin: EntryOrigin::Control {
            control_kind: ControlKind::CLOSE_TRANSITION,
            spec_body_digest: body.digest().map_err(encode)?,
        },
        principal_ref: principal,
        session_ref: None,
        evidence: Vec::new(),
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: if matches!(kind, RecordKind::Open) {
            vec![(
                fa_model::entry::CLOSE_RUN_EXTENSION,
                body.canonical_bytes().map_err(encode)?,
            )]
        } else {
            Vec::new()
        },
        tags: Vec::new(),
    })
}

fn object_props(
    book: &BookContext,
    code: &str,
    payload: Vec<u8>,
    digest: [u8; 32],
    state: i64,
) -> Result<Vec<(fgdb_delta_types::PropertyKeyId, CanonicalScalar)>, KernelError> {
    let mut props = vec![
        (
            property::FA_PAYLOAD,
            scalar_bytes("close._fa_payload", payload)?,
        ),
        (
            property::FA_DIGEST,
            scalar_bytes("close._fa_digest", digest.to_vec())?,
        ),
        (
            property::BOOK_ID,
            scalar_bytes("close.book_id", book.book_id.0.to_vec())?,
        ),
        (property::CODE, scalar_text("close.code", code)?),
        (property::STATE, CanonicalScalar::Int(state)),
    ];
    props.sort_by_key(|(key, _)| key.0);
    Ok(props)
}

fn add_record(
    batch: &mut WriteBatch,
    tracker: &mut TemplateByteTracker,
    proposal: EntryPayload,
    object: VId,
) -> Result<VId, KernelError> {
    let vid = entry_vid(
        proposal.book_id,
        &proposal.principal_ref.0.to_le_bytes(),
        &proposal.idempotency_key,
    );
    let entry = proposal.seal(Vec::new(), None)?;
    let mirrors = entry_mirrors(&entry)?;
    tracker.create_vertex(relation::IN_CASE, vid, 1, &mirrors);
    batch.create_vertex(vid, vec![label::ENTRY], mirrors);
    tracker.add_edge(relation::IN_CASE, &[]);
    batch.add_edge(edge_id(relation::IN_CASE, vid, object), vid, object, vec![]);
    Ok(vid)
}

/// Journal the immutable graph. Exact retries return the existing run.
pub async fn create_close_run<V: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    definition: &CloseRunDefinition,
    capability: &Capability,
    description: Erasable<String>,
) -> Outcome<CloseRunView> {
    if let Err(refusal) = admit(db, book, capability, Some("Open"))? {
        return Ok(Err(refusal));
    }
    let body = match definition_body(book, definition, capability.holder())? {
        Ok(body) => body,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if let Err(refusal) = crate::scratch::ensure_history(db, cx).await? {
        return Ok(Err(refusal));
    }
    if let Some(view) = read_view(db, cx, book, &body.name)? {
        return if view.body == body {
            Ok(Ok(view))
        } else {
            Ok(Err(conflict(
                "this run name already binds another definition",
            )))
        };
    }
    if db
        .vertex(period_vid(&book.calendar.id, &body.period))?
        .is_none()
    {
        return Ok(Err(invalid(
            "the close run's period does not exist in this book",
        )));
    }
    for task in &body.tasks {
        if let Err(refusal) = validate_draft(db, cx, book, &body.period, task)? {
            return Ok(Err(refusal));
        }
    }
    let run = close_run_vid(book.book_id, &body.name);
    let mut txn = db.begin(&cx.txn())?;
    if let Err(refusal) = policy::capability_witness(&txn, db, book, capability)? {
        txn.abort();
        return Ok(Err(refusal));
    }
    if txn.vertex(db, run)?.is_some() {
        txn.abort();
        return Ok(Err(conflict("the close run appeared during creation")));
    }
    txn.vertex(db, period_vid(&book.calendar.id, &body.period))?;
    let mut batch = WriteBatch::new(relation::IN_CASE);
    let mut dependencies = WriteBatch::new(relation::DEPENDS_ON);
    let mut tracker = TemplateByteTracker::default();
    let props = object_props(
        book,
        &body.name,
        body.canonical_bytes().map_err(encode)?,
        body.digest().map_err(encode)?,
        1,
    )?;
    tracker.create_vertex(relation::IN_CASE, run, 1, &props);
    batch.create_vertex(run, vec![label::CLOSE_RUN], props);
    add_record(
        &mut batch,
        &mut tracker,
        proposal(
            book,
            &body,
            RecordKind::Open,
            run,
            capability.holder(),
            description,
            None,
        )?,
        run,
    )?;
    for task in &body.tasks {
        let vid = close_task_vid(book.book_id, &body.name, &task.id);
        if txn.vertex(db, vid)?.is_some() {
            txn.abort();
            return Ok(Err(conflict("a close task identity already exists")));
        }
        if let CloseTaskBodyAction::PromoteDraft {
            draft,
            certificate_digest,
            ..
        } = &task.action
        {
            txn.vertex(db, *draft)?;
            txn.in_neighbours(db, *draft, relation::IN_CASE)?;
            txn.vertex(db, report_certificate_vid(book.book_id, certificate_digest))?;
        }
        let props = object_props(
            book,
            &task.id,
            task.canonical_bytes().map_err(encode)?,
            task.digest().map_err(encode)?,
            0,
        )?;
        tracker.create_vertex(relation::IN_CASE, vid, 1, &props);
        batch.create_vertex(vid, vec![label::CLOSE_TASK], props);
        tracker.add_edge(relation::IN_CASE, &[]);
        batch.add_edge(edge_id(relation::IN_CASE, vid, run), vid, run, vec![]);
        for dependency in &task.depends_on {
            let prerequisite = close_task_vid(book.book_id, &body.name, dependency);
            tracker.add_edge(relation::DEPENDS_ON, &[]);
            dependencies.add_edge(
                edge_id(relation::DEPENDS_ON, vid, prerequisite),
                vid,
                prerequisite,
                vec![],
            );
        }
    }
    if tracker.total_bytes() > fa_model::limits::MAX_BATCH_TEMPLATE_BYTES {
        txn.abort();
        return Ok(Err(crate::batch::batch_byte_budget_refusal(
            tracker.total_bytes(),
            None,
            body.tasks.len(),
        )));
    }
    let mut batches = vec![batch];
    if !dependencies.is_empty() {
        batches.push(dependencies);
    }
    txn.write_ordered(db, batches)?;
    if let Err(denial) = fa_policy::current(capability, db.frontier()?) {
        txn.abort();
        return Ok(Err(policy::refusal(&denial)));
    }
    match txn.commit(db, &cx.commit()).await {
        Ok(_) => {}
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            return Ok(Err(conflict(detail)));
        }
        Err(error) => return Err(error.into()),
    }
    Ok(Ok(
        read_view(db, cx, book, &body.name)?.ok_or_else(|| corrupt("published run is absent"))?
    ))
}

/// Reconstruct completion from immutable CloseControl entries and same-commit
/// native effects. Mutable STATE and graph mirrors are checked, not trusted.
pub fn close_run_status<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    name: &str,
    capability: &Capability,
) -> Outcome<Option<CloseRunView>> {
    if let Err(refusal) = admit(db, book, capability, None)? {
        return Ok(Err(refusal));
    }
    Ok(Ok(read_view(db, cx, book, name)?))
}

fn read_view<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    name: &str,
) -> Result<Option<CloseRunView>, KernelError> {
    let run = close_run_vid(book.book_id, name);
    let Some(row) = db.vertex(run)? else {
        return Ok(None);
    };
    crate::entry_history::verify_entry_history(db, cx, book, None)?;
    let body = CloseRunBody::decode(&bytes(&row, property::FA_PAYLOAD, "CloseRun payload")?)
        .map_err(|e| corrupt(e.to_string()))?;
    if body.book_id != book.book_id || body.name != name {
        return Err(corrupt("run identity/body mismatch"));
    }
    let digest = body.digest().map_err(encode)?;
    let tasks: BTreeMap<_, _> = body
        .tasks
        .iter()
        .map(|task| (close_task_vid(book.book_id, name, &task.id), task))
        .collect();
    let mut records = Vec::new();
    let known_at = db.frontier()?;
    for row in db.vertices_at(known_at)? {
        cx.query()
            .checkpoint()
            .map_err(WriteTxnError::Interrupted)?;
        if !row.labels.contains(&label::ENTRY) {
            continue;
        }
        let entry = crate::entry_storage::decode_at(db, &row, known_at)?;
        let seq = row.created_at;
        if let Some(ControlPayload::LifecycleTransition { object_ref, .. }) =
            &entry.proposal.control
            && (*object_ref == run || tasks.contains_key(object_ref))
        {
            records.push((seq, row.vid, entry));
        }
    }
    records.sort_by_key(|(seq, vid, _)| (*seq, *vid));
    let mut opened_at = None;
    let mut completed_at = None;
    let mut completions = BTreeMap::<VId, CloseTaskReceipt>::new();
    let mut task_reviews = BTreeMap::<VId, Option<[u8; 32]>>::new();
    let mut reviews = Vec::<CloseRunReviewReceipt>::new();
    let mut expected_edges = BTreeSet::new();
    for (seq, vid, entry) in &records {
        let p = &entry.proposal;
        let Some(ControlPayload::LifecycleTransition {
            object_ref,
            from,
            to,
            proof_refs,
            reason_code,
        }) = &p.control
        else {
            return Err(corrupt("record lacks lifecycle"));
        };
        if p.class != EntryClass::CLOSE_CONTROL
            || p.book_id != book.book_id
            || p.branch_id != Id128::TRUNK
            || p.origin
                != (EntryOrigin::Control {
                    control_kind: ControlKind::CLOSE_TRANSITION,
                    spec_body_digest: digest,
                })
            || *reason_code != 0
            || !entry.approvals.is_empty()
            || entry.plan_certificate.is_some()
        {
            return Err(corrupt("foreign or malformed close control"));
        }
        let kind = if *object_ref == run {
            match (*from, *to) {
                (0, 1)
                    if opened_at.is_none()
                        && p.principal_ref == body.owner
                        && proof_refs.is_empty()
                        && p.extensions
                            == vec![(
                                fa_model::entry::CLOSE_RUN_EXTENSION,
                                body.canonical_bytes().map_err(encode)?,
                            )] =>
                {
                    opened_at = Some(*seq);
                    RecordKind::Open
                }
                (1, 2)
                    if completed_at.is_none()
                        && p.extensions.is_empty()
                        && proof_refs.len() == 1 =>
                {
                    completed_at = Some((*seq, proof_refs[0], p.principal_ref));
                    RecordKind::Complete
                }
                (1, 1) if p.extensions.is_empty() => {
                    let [TypedRef::Object(certificate)] = proof_refs.as_slice() else {
                        return Err(corrupt("a combined review names exactly one certificate"));
                    };
                    if reviews.len() >= MAX_TASKS
                        || reviews.iter().any(|review| {
                            review.certificate == certificate.0 || review.recorded_at == *seq
                        })
                    {
                        return Err(corrupt("a combined review is duplicated or out of bounds"));
                    }
                    let retained =
                        db.vertex(report_certificate_vid(book.book_id, &certificate.0))?;
                    if retained.as_ref().is_none_or(|row| {
                        row.created_at >= *seq || !certificate_row(row, book, &certificate.0)
                    }) {
                        return Err(corrupt(
                            "a selected combined review has no original retained artifact",
                        ));
                    }
                    reviews.push(CloseRunReviewReceipt {
                        record: *vid,
                        certificate: certificate.0,
                        recorded_at: *seq,
                        principal: p.principal_ref,
                    });
                    RecordKind::Review
                }
                _ => {
                    return Err(corrupt(
                        "run lifecycle must contain one Open, bounded review selections and at most one Complete",
                    ));
                }
            }
        } else {
            if (*from, *to) != (0, 1) || !p.extensions.is_empty() {
                return Err(corrupt("invalid task completion transition"));
            }
            let (effect, review) = match proof_refs.as_slice() {
                [TypedRef::Vertex(effect)] => (*effect, None),
                [TypedRef::Vertex(effect), TypedRef::Object(review)] => (*effect, Some(review.0)),
                _ => {
                    return Err(corrupt(
                        "task completion names one native effect and optionally its selected combined review",
                    ));
                }
            };
            let task = tasks
                .get(object_ref)
                .ok_or_else(|| corrupt("completion target is absent"))?;
            verify_effect(
                db,
                cx,
                book,
                &body.period,
                task,
                effect,
                *seq,
                p.principal_ref,
            )?;
            if completions
                .insert(
                    *object_ref,
                    CloseTaskReceipt {
                        record: *vid,
                        effect,
                        recorded_at: *seq,
                        principal: p.principal_ref,
                    },
                )
                .is_some()
            {
                return Err(corrupt("task completed more than once"));
            }
            task_reviews.insert(*object_ref, review);
            RecordKind::Task
        };
        let expected_key = if matches!(kind, RecordKind::Review) {
            let [TypedRef::Object(certificate)] = proof_refs.as_slice() else {
                return Err(corrupt("combined review identity lacks its certificate"));
            };
            review_key(*object_ref, &certificate.0)
        } else {
            record_key(kind, *object_ref)
        };
        if p.idempotency_key != expected_key
            || *vid
                != entry_vid(
                    book.book_id,
                    &p.principal_ref.0.to_le_bytes(),
                    &p.idempotency_key,
                )
        {
            return Err(corrupt("close control has a noncanonical identity"));
        }
        expected_edges.insert((relation::IN_CASE, *vid, *object_ref));
    }
    let opened_at = opened_at.ok_or_else(|| corrupt("run has no original Open record"))?;
    // First use is evidence of an actual native publication, not a separately
    // mutable promise. No review may exist without its same-commit task, and a
    // later task cannot silently fall back to a prior or absent selection.
    for review in &reviews {
        if review.recorded_at <= opened_at
            || !completions.iter().any(|(task, receipt)| {
                receipt.recorded_at == review.recorded_at
                    && receipt.principal == review.principal
                    && task_reviews.get(task) == Some(&Some(review.certificate))
            })
        {
            return Err(corrupt(
                "combined review selection has no same-commit first task",
            ));
        }
    }
    for (task, receipt) in &completions {
        let selected = reviews
            .iter()
            .rev()
            .find(|review| review.recorded_at <= receipt.recorded_at);
        if task_reviews.get(task).copied().flatten() != selected.map(|review| review.certificate) {
            return Err(corrupt(
                "task completion dropped or substituted its current combined review",
            ));
        }
    }
    let complete = completions.len() == body.tasks.len();
    match (&completed_at, complete) {
        (Some((seq, TypedRef::Vertex(last), principal)), true) => {
            if !completions.values().any(|receipt| {
                receipt.record == *last
                    && receipt.recorded_at == *seq
                    && receipt.principal == *principal
            }) || completions
                .values()
                .any(|receipt| receipt.recorded_at > *seq)
            {
                return Err(corrupt(
                    "run completion does not share the final task's publication",
                ));
            }
        }
        (None, false) => {}
        _ => return Err(corrupt("run completion disagrees with completed tasks")),
    }
    let expected_run = object_props(
        book,
        name,
        body.canonical_bytes().map_err(encode)?,
        digest,
        if complete { 2 } else { 1 },
    )?;
    if row.labels.as_slice() != [label::CLOSE_RUN]
        || row.retired_at.is_some()
        || row.props != expected_run
    {
        return Err(corrupt(
            "run mirrors differ from its immutable definition and lifecycle",
        ));
    }
    let mut views = Vec::with_capacity(body.tasks.len());
    let mut state_changes = BTreeMap::from([(run, vec![opened_at])]);
    if let Some((seq, _, _)) = completed_at {
        state_changes
            .get_mut(&run)
            .ok_or_else(|| corrupt("run state witness"))?
            .push(seq);
    }
    for task in &body.tasks {
        let vid = close_task_vid(book.book_id, name, &task.id);
        let completion = completions.get(&vid).cloned();
        let task_row = db
            .vertex(vid)?
            .ok_or_else(|| corrupt("declared task is absent"))?;
        let props = object_props(
            book,
            &task.id,
            task.canonical_bytes().map_err(encode)?,
            task.digest().map_err(encode)?,
            i64::from(completion.is_some()),
        )?;
        if task_row.labels.as_slice() != [label::CLOSE_TASK]
            || task_row.retired_at.is_some()
            || task_row.props != props
        {
            return Err(corrupt(
                "task mirrors differ from its declaration and completion record",
            ));
        }
        expected_edges.insert((relation::IN_CASE, vid, run));
        let mut changes = vec![opened_at];
        if let Some(receipt) = &completion {
            if receipt.recorded_at <= opened_at {
                return Err(corrupt("task completion precedes its run"));
            }
            changes.push(receipt.recorded_at);
        }
        state_changes.insert(vid, changes);
        let mut prerequisites_complete = true;
        for dependency in &task.depends_on {
            let prerequisite = close_task_vid(book.book_id, name, dependency);
            expected_edges.insert((relation::DEPENDS_ON, vid, prerequisite));
            let prior = completions.get(&prerequisite);
            prerequisites_complete &= prior.is_some();
            if let Some(receipt) = &completion
                && prior.is_none_or(|prior| prior.recorded_at >= receipt.recorded_at)
            {
                return Err(corrupt("a task completed before its prerequisites"));
            }
        }
        views.push(CloseTaskView {
            vid,
            id: task.id.clone(),
            ready: completion.is_none() && prerequisites_complete,
            completion,
            rehearsal: task_reviews.get(&vid).copied().flatten(),
        });
    }
    let selected: BTreeSet<_> = state_changes.keys().copied().collect();
    let mut found_edges = BTreeSet::new();
    for edge in db.edges_at(db.frontier()?)? {
        let e = &edge.entry;
        if matches!(e.relation, relation::IN_CASE | relation::DEPENDS_ON)
            && (selected.contains(&e.src) || selected.contains(&e.dst))
        {
            let signature = (e.relation, e.src, e.dst);
            if e.eid != edge_id(e.relation, e.src, e.dst)
                || !expected_edges.contains(&signature)
                || !found_edges.insert(signature)
            {
                return Err(corrupt(
                    "close membership/dependency graph differs from its original declaration",
                ));
            }
        }
    }
    if found_edges != expected_edges {
        return Err(corrupt("close membership/dependency edge is missing"));
    }
    // Detect edits followed by restoration: a definition is immutable, and
    // only its recorded lifecycle may move its STATE projection.
    let mut births = BTreeSet::new();
    for batch in db.delta_since(CommitSeq(0))? {
        let seq = batch.commit_seq();
        for coordinate in batch.coordinate_entries() {
            for delta in &coordinate.rows {
                match delta {
                    DeltaRow::CreateVertex { vid, .. } if selected.contains(vid) => {
                        if seq != opened_at || !births.insert(*vid) {
                            return Err(corrupt("close object has no unique original birth"));
                        }
                    }
                    DeltaRow::Property {
                        elem: ElementId::Vertex(vid),
                        property: key,
                        ..
                    } if selected.contains(vid) => {
                        if seq != opened_at
                            && (*key != property::STATE || !state_changes[vid].contains(&seq))
                        {
                            return Err(corrupt(
                                "close definition was modified after its original declaration",
                            ));
                        }
                    }
                    DeltaRow::LabelMembership { vid, .. }
                        if selected.contains(vid) && seq != opened_at =>
                    {
                        return Err(corrupt("close object labels were modified"));
                    }
                    DeltaRow::DeleteVertex { vid, .. } if selected.contains(vid) => {
                        return Err(corrupt("close object was retired"));
                    }
                    _ => {}
                }
            }
        }
    }
    if births != selected {
        return Err(corrupt("close object lacks its native creation history"));
    }
    Ok(Some(CloseRunView {
        vid: run,
        body,
        opened_at,
        complete,
        tasks: views,
        reviews,
    }))
}

#[allow(clippy::too_many_arguments)]
fn verify_effect<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    period: &str,
    task: &CloseTaskBody,
    effect: VId,
    seq: CommitSeq,
    principal: VId,
) -> Result<(), KernelError> {
    let row = db
        .vertex(effect)?
        .ok_or_else(|| corrupt("task's native effect is absent"))?;
    let entry = crate::entry_storage::decode_at(db, &row, seq)?;
    let recorded_at = row.created_at;
    if recorded_at != seq || entry.proposal.principal_ref != principal {
        return Err(corrupt(
            "task receipt and native effect were not published atomically by one principal",
        ));
    }
    match &task.action {
        CloseTaskBodyAction::PromoteDraft {
            draft,
            name,
            owner,
            entry_count,
            entries_digest: expected,
            ..
        } => {
            if entry.proposal.class != EntryClass::DRAFT_CONTROL
                || !matches!(&entry.proposal.control, Some(ControlPayload::LifecycleTransition { object_ref, from: 1, to: 2, .. }) if object_ref == draft)
            {
                return Err(corrupt("task does not name its native draft promotion"));
            }
            let view = crate::draft::read_draft(db, &cx.query(), book, name)?
                .ok_or_else(|| corrupt("promoted draft is absent"))?;
            if view.body.vid() != *draft
                || view.body.owner != *owner
                || entry.proposal.origin
                    != (EntryOrigin::Control {
                        control_kind: ControlKind::DRAFT_TRANSITION,
                        spec_body_digest: view.body.digest()?,
                    })
            {
                return Err(corrupt(
                    "completed draft body differs from its declaration and native promotion",
                ));
            }
            let closure = view
                .closed
                .ok_or_else(|| corrupt("completed draft has no closure"))?;
            let (outcome, entries) = closure
                .promoted
                .ok_or_else(|| corrupt("completed draft has no promotion outcome"))?;
            if closure.record != effect
                || closure.recorded_at != seq
                || entries.len() != *entry_count as usize
                || entries_digest(&entries)? != *expected
            {
                return Err(corrupt(
                    "completed draft differs from the exact reviewed entry effects",
                ));
            }
            let outcome_row = db
                .vertex(outcome)?
                .ok_or_else(|| corrupt("completed draft outcome is absent"))?;
            if outcome_row.created_at != seq {
                return Err(corrupt(
                    "completed draft outcome was not preserved from its native publication",
                ));
            }
            for expected in &entries {
                let row = db.vertex(expected.vid)?.ok_or_else(|| {
                    corrupt("a completed draft's actual monetary entry is absent")
                })?;
                let actual = crate::entry_storage::decode_at(db, &row, seq)?;
                let published = row.created_at;
                if published != seq
                    || actual.entry_ref(expected.vid) != *expected
                    || actual.proposal.book_id != book.book_id
                    || actual.proposal.branch_id != Id128::TRUNK
                {
                    return Err(corrupt(
                        "completed draft entry effects were not published in the receipt's atomic transaction",
                    ));
                }
            }
        }
        CloseTaskBodyAction::PeriodTransition { to: expected } => {
            if entry.proposal.class != EntryClass::PERIOD_CONTROL
                || !matches!(&entry.proposal.control, Some(ControlPayload::PeriodTransition { period_ref, to, .. }) if period_ref.calendar == book.calendar.id && period_ref.code == period && to == expected)
            {
                return Err(corrupt(
                    "task does not name its declared native period transition",
                ));
            }
        }
    }
    Ok(())
}

fn ready_task<'a>(
    view: &'a CloseRunView,
    id: &str,
) -> Result<(&'a CloseTaskView, &'a CloseTaskBody), Refusal> {
    let task = view
        .tasks
        .iter()
        .find(|task| task.id == id)
        .ok_or_else(|| invalid(format!("close run has no task `{id}`")))?;
    let body = view
        .body
        .tasks
        .iter()
        .find(|task| task.id == id)
        .ok_or_else(|| invalid("task has no declaration"))?;
    if !task.ready && task.completion.is_none() {
        return Err(invalid(format!(
            "close task `{id}` still has unfinished prerequisites"
        )));
    }
    Ok((task, body))
}

fn validate_task_review<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    view: &CloseRunView,
    task: &CloseTaskView,
    review: Option<&CloseTaskReview>,
) -> Outcome<()> {
    let Some(review) = review else {
        return Ok(if task.completion.is_none() && !view.reviews.is_empty() {
            Err(review_invalidated(
                "this close run has a durable combined review; execution cannot omit it",
            ))
        } else {
            Ok(())
        });
    };
    if review.book != book.book_id
        || review.run != view.vid
        || review.body_digest != view.body.digest().map_err(encode)?
        || review.opened_at != view.opened_at
    {
        return Ok(Err(review_invalidated(
            "the selected combined review names a different book or close graph",
        )));
    }
    if review.checked_at != db.frontier()? {
        return Ok(Err(review_invalidated(
            "the source frontier changed after the combined close was checked",
        )));
    }
    if task.completion.is_some() && task.rehearsal != Some(review.certificate) {
        return Ok(Err(conflict(
            "a completed task cannot substitute its original combined review",
        )));
    }
    if task.completion.is_none()
        && view
            .reviews
            .last()
            .is_some_and(|current| current.certificate != review.certificate)
        && view
            .reviews
            .iter()
            .any(|prior| prior.certificate == review.certificate)
    {
        return Ok(Err(review_invalidated(
            "a superseded combined review cannot become current again",
        )));
    }
    let retained = db.vertex(report_certificate_vid(book.book_id, &review.certificate))?;
    if retained
        .as_ref()
        .is_none_or(|row| !certificate_row(row, book, &review.certificate))
    {
        return Ok(Err(review_invalidated(
            "the selected combined close review is not retained in this book",
        )));
    }
    Ok(Ok(()))
}

/// Review the native final transition, including its exact sealed proposal.
/// Execution still requires the ordinary independently recorded approvals.
#[allow(clippy::too_many_arguments)]
pub fn plan_close_task_transition<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    name: &str,
    task_id: &str,
    capability: &Capability,
    reason_code: u16,
    key: &[u8],
    description: Erasable<String>,
) -> Outcome<TransitionPlan> {
    if let Err(refusal) = admit(db, book, capability, Some("CompleteTask"))? {
        return Ok(Err(refusal));
    }
    let Some(view) = read_view(db, cx, book, name)? else {
        return Ok(Err(invalid("the close run does not exist")));
    };
    let (task, body) = match ready_task(&view, task_id) {
        Ok(task) => task,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if task.completion.is_some() {
        return Ok(Err(invalid("the close task is already complete")));
    }
    let CloseTaskBodyAction::PeriodTransition { to } = body.action else {
        return Ok(Err(invalid(
            "only the final period task takes a transition plan",
        )));
    };
    crate::period::plan_transition(
        db,
        book,
        &view.body.period,
        transition(to)?,
        capability.holder(),
        reason_code,
        key,
        description,
    )
}

/// An unforgeable in-crate attachment carried into the native transaction.
/// All close state and authority are re-witnessed before any receipt is staged.
pub(crate) struct TaskCompletion {
    view: CloseRunView,
    task: String,
    capability: Capability,
    description: Erasable<String>,
    review: Option<CloseTaskReview>,
}

impl TaskCompletion {
    pub(crate) fn stage<V: Vfs + Clone>(
        &self,
        txn: &mut WriteTxn,
        tracker: &mut TemplateByteTracker,
        db: &mut Database<V>,
        book: &BookContext,
        effect: VId,
        entries: Option<&[EntryRef]>,
    ) -> Outcome<()> {
        if let Err(refusal) = policy::capability_witness(txn, db, book, &self.capability)? {
            return Ok(Err(refusal));
        }
        let (selected, body) = match ready_task(&self.view, &self.task) {
            Ok(task) => task,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if let Err(refusal) =
            validate_task_review(db, book, &self.view, selected, self.review.as_ref())?
        {
            return Ok(Err(refusal));
        }
        for (vid, expected_state) in std::iter::once((self.view.vid, 1)).chain(
            self.view
                .tasks
                .iter()
                .map(|task| (task.vid, i64::from(task.completion.is_some()))),
        ) {
            let Some(row) = txn.vertex(db, vid)? else {
                return Err(corrupt("staged task/run is absent"));
            };
            if prop(&row, property::STATE) != Some(&CanonicalScalar::Int(expected_state)) {
                return Ok(Err(conflict("close task state changed during execution")));
            }
        }
        if let CloseTaskBodyAction::PromoteDraft {
            certificate_digest,
            entry_count,
            entries_digest: expected,
            ..
        } = &body.action
        {
            let Some(entries) = entries else {
                return Err(corrupt("draft completion carries no native entry effects"));
            };
            if entries.len() != *entry_count as usize || entries_digest(entries)? != *expected {
                return Ok(Err(invalid(
                    "the native promotion no longer matches the exact reviewed close effects",
                )));
            }
            let retained =
                txn.vertex(db, report_certificate_vid(book.book_id, certificate_digest))?;
            if retained
                .as_ref()
                .is_none_or(|row| !certificate_row(row, book, certificate_digest))
            {
                return Ok(Err(invalid(
                    "the bound close certificate is no longer retained",
                )));
            }
        } else if entries.is_some() {
            return Err(corrupt(
                "period completion unexpectedly carries draft entries",
            ));
        }
        let mut batch = WriteBatch::new(relation::IN_CASE);
        let review_digest = self.review.as_ref().map(|review| review.certificate);
        if let Some(review) = &self.review {
            let retained = txn.vertex(
                db,
                report_certificate_vid(book.book_id, &review.certificate),
            )?;
            if retained
                .as_ref()
                .is_none_or(|row| !certificate_row(row, book, &review.certificate))
            {
                return Ok(Err(review_invalidated(
                    "the selected combined close review changed before publication",
                )));
            }
            if self
                .view
                .reviews
                .last()
                .is_none_or(|current| current.certificate != review.certificate)
            {
                let mut selection = proposal(
                    book,
                    &self.view.body,
                    RecordKind::Review,
                    self.view.vid,
                    self.capability.holder(),
                    self.description.clone(),
                    None,
                )?;
                selection.idempotency_key = review_key(self.view.vid, &review.certificate);
                let Some(ControlPayload::LifecycleTransition { proof_refs, .. }) =
                    &mut selection.control
                else {
                    return Err(corrupt(
                        "combined review selection has no lifecycle payload",
                    ));
                };
                proof_refs.push(TypedRef::Object(Oid(review.certificate)));
                let selection_vid = entry_vid(
                    book.book_id,
                    &self.capability.holder().0.to_le_bytes(),
                    &selection.idempotency_key,
                );
                if txn.vertex(db, selection_vid)?.is_some() {
                    return Ok(Err(conflict(
                        "the combined review selection appeared during execution",
                    )));
                }
                add_record(&mut batch, tracker, selection, self.view.vid)?;
            }
        }
        let mut task_record = proposal(
            book,
            &self.view.body,
            RecordKind::Task,
            selected.vid,
            self.capability.holder(),
            self.description.clone(),
            Some(effect),
        )?;
        if let Some(digest) = review_digest {
            let Some(ControlPayload::LifecycleTransition { proof_refs, .. }) =
                &mut task_record.control
            else {
                return Err(corrupt("task completion has no lifecycle payload"));
            };
            proof_refs.push(TypedRef::Object(Oid(digest)));
        }
        let receipt = add_record(&mut batch, tracker, task_record, selected.vid)?;
        tracker.set_vertex_property(
            relation::IN_CASE,
            selected.vid,
            property::STATE,
            Some(CanonicalScalar::Int(0)),
            Some(CanonicalScalar::Int(1)),
        );
        batch.compare_and_set_vertex_property(
            selected.vid,
            property::STATE,
            Some(CanonicalScalar::Int(0)),
            CanonicalScalar::Int(1),
            WriteMismatchPolicy::AbortWrite,
        );
        if self
            .view
            .tasks
            .iter()
            .all(|task| task.vid == selected.vid || task.completion.is_some())
        {
            if let Err(refusal) = admit(db, book, &self.capability, Some("Complete"))? {
                return Ok(Err(refusal));
            }
            add_record(
                &mut batch,
                tracker,
                proposal(
                    book,
                    &self.view.body,
                    RecordKind::Complete,
                    self.view.vid,
                    self.capability.holder(),
                    self.description.clone(),
                    Some(receipt),
                )?,
                self.view.vid,
            )?;
            tracker.set_vertex_property(
                relation::IN_CASE,
                self.view.vid,
                property::STATE,
                Some(CanonicalScalar::Int(1)),
                Some(CanonicalScalar::Int(2)),
            );
            batch.compare_and_set_vertex_property(
                self.view.vid,
                property::STATE,
                Some(CanonicalScalar::Int(1)),
                CanonicalScalar::Int(2),
                WriteMismatchPolicy::AbortWrite,
            );
        }
        // The effect's transaction may be staged in another relation (a
        // period transition's): append the receipt as a dependent group.
        txn.write_ordered(db, vec![batch])?;
        if tracker.total_bytes() > fa_model::limits::MAX_BATCH_TEMPLATE_BYTES {
            return Ok(Err(crate::batch::batch_byte_budget_refusal(
                tracker.total_bytes(),
                None,
                2,
            )));
        }
        Ok(Ok(()))
    }
}

/// Execute one ready task. All normal native admission and approval laws
/// apply. An identical retry returns its original receipt without posting.
pub async fn execute_close_task<V: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    name: &str,
    task_id: &str,
    request: CloseTaskRequest,
) -> Outcome<CloseTaskRecorded> {
    if let Err(refusal) = admit(db, book, &request.capability, Some("CompleteTask"))? {
        return Ok(Err(refusal));
    }
    if let Err(refusal) = crate::scratch::ensure_history(db, cx).await? {
        return Ok(Err(refusal));
    }
    let Some(view) = read_view(db, cx, book, name)? else {
        return Ok(Err(invalid("the close run does not exist")));
    };
    let (task, body) = match ready_task(&view, task_id) {
        Ok(task) => task,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if let Err(refusal) = validate_task_review(db, book, &view, task, request.review.as_ref())? {
        return Ok(Err(refusal));
    }
    if let CloseTaskBodyAction::PromoteDraft { owner, .. } = &body.action {
        if request.transition_plan.is_some() || !request.approvals.is_empty() {
            return Ok(Err(invalid(
                "draft close tasks use their retained native approvals; a transition plan or extra approval would be ignored",
            )));
        }
        if let Err(denial) = fa_policy::require(
            &request.capability,
            Op::Approve,
            "execute or retry a close draft promotion",
        ) {
            return Ok(Err(policy::refusal(&denial)));
        }
        if *owner == request.capability.holder() {
            return Ok(Err(policy::refusal(&fa_policy::Denial::SelfApproval {
                rule: "draft-promote".into(),
                approver: *owner,
            })));
        }
    }
    if let CloseTaskBodyAction::PeriodTransition { to } = &body.action {
        if let Some(plan) = &request.transition_plan {
            if plan.period_code != view.body.period
                || plan.book_id != book.book_id
                || plan.to.tag() != *to
                || plan.principal_ref != request.capability.holder()
            {
                return Ok(Err(invalid(
                    "the transition plan does not select this close task and executor",
                )));
            }
            let digest = match plan.proposal_digest(book)? {
                Ok(digest) => digest,
                Err(refusal) => return Ok(Err(refusal)),
            };
            if let Some(receipt) = &task.completion {
                let row = db
                    .vertex(receipt.effect)?
                    .ok_or_else(|| corrupt("completed native transition is absent"))?;
                let entry = crate::entry_storage::decode_at(db, &row, receipt.recorded_at)?;
                if entry.proposal.proposal_digest()? != digest
                    || entry.approvals != request.approvals
                {
                    return Ok(Err(conflict(
                        "the supplied transition plan or approvals differ from the completed native effect",
                    )));
                }
            }
        } else if task.completion.is_none() || !request.approvals.is_empty() {
            return Ok(Err(invalid(
                "the final period task requires its reviewed native transition plan",
            )));
        }
    }
    if let Some(receipt) = task.completion.clone() {
        return Ok(Ok(CloseTaskRecorded {
            run: view,
            task: task_id.into(),
            receipt,
            already_recorded: true,
        }));
    }
    let completion = TaskCompletion {
        view: view.clone(),
        task: task_id.into(),
        capability: request.capability.clone(),
        description: request.description.clone(),
        review: request.review.clone(),
    };
    match &body.action {
        CloseTaskBodyAction::PromoteDraft {
            name: draft_name, ..
        } => {
            if let Err(refusal) = validate_draft(db, cx, book, &view.body.period, body)? {
                return Ok(Err(refusal));
            }
            let req = DraftRequest {
                capability: request.capability,
                effective_date: DateDay(0),
                description: request.description,
            };
            if let Err(refusal) =
                crate::draft::promote_draft_for_close(db, cx, book, draft_name, req, &completion)
                    .await?
            {
                return Ok(Err(refusal));
            }
        }
        CloseTaskBodyAction::PeriodTransition { to } => {
            let Some(plan) = &request.transition_plan else {
                return Ok(Err(invalid(
                    "the final period task requires its reviewed native transition plan",
                )));
            };
            if plan.period_code != view.body.period
                || plan.book_id != book.book_id
                || plan.to.tag() != *to
                || plan.principal_ref != request.capability.holder()
            {
                return Ok(Err(invalid(
                    "the transition plan does not select this close task and executor",
                )));
            }
            if let Err(refusal) = crate::period::transition_planned_for_close(
                db,
                cx,
                book,
                plan,
                transition(*to)?,
                &request.capability,
                &request.approvals,
                &completion,
            )
            .await?
            {
                return Ok(Err(refusal));
            }
        }
    }
    let run = read_view(db, cx, book, name)?.ok_or_else(|| corrupt("executed run disappeared"))?;
    let receipt = run
        .tasks
        .iter()
        .find(|task| task.id == task_id)
        .and_then(|task| task.completion.clone())
        .ok_or_else(|| corrupt("native effect returned without its atomic close receipt"))?;
    Ok(Ok(CloseTaskRecorded {
        run,
        task: task_id.into(),
        receipt,
        already_recorded: false,
    }))
}
