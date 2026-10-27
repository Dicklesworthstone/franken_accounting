//! Approved monthly fixed-entry schedules (plan §7.6; fa-0bi).
//!
//! A schedule journals the complete template, cadence and execution capability.
//! Its independent approval authorizes only those fixed effects. Every occurrence
//! passes the ordinary posting pipeline under the creator's *current* capability;
//! a committed, corroborated TimeEvidence tick supplies its only clock input.
//! Cancellation, next-index advancement and occurrence publication have point
//! witnesses in the same transaction. The mutable schedule row is a checked
//! projection of immutable creation, occurrence and cancellation records.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_model::entry::{RECURRING_OCCURRENCE_EXTENSION, RECURRING_SCHEDULE_EXTENSION};
use fa_model::symbols::{label, property, relation};
use fa_model::{
    ApprovalRef, ControlKind, ControlPayload, Entry, EntryClass, EntryOrigin, EntryPayload,
    EntryRef, Erasable, Id128, Reader, ScheduleTrigger, Writer, domain_digest, entry_mirrors,
    entry_vid,
};
use fa_policy::{Capability, Intent, Op, Party, Profile, Reach};
use fa_time::{DateDay, MonthEndPolicy, MonthlyRecurrence};
use fgdb::{Database, WriteBatch, WriteMismatchPolicy, WriteTxn, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::genesis::BookContext;
use crate::policy;
use crate::post::{PostPreparation, PostRequest};
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{bytes, edge_id, scalar_bytes, scalar_text};
use crate::sweep::{SweepRequest, Tick, conflict, decode_entry};

const VERSION: u16 = 1;
const ACTIVE: i64 = 1;
const CANCELLED: i64 = 2;
const MAX_BODY_BYTES: usize = 32_768;
const MAX_NAME_BYTES: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecurringSpec {
    pub name: String,
    /// The effective date is the anchor. Description, evidence and ordered
    /// legs are fixed; every occurrence derives its own date, key and origin.
    pub template: EntryPayload,
    pub every_months: u32,
    pub month_end: MonthEndPolicy,
    /// Inclusive final effective date; None is explicitly open-ended.
    pub end: Option<DateDay>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecurringPlan {
    spec: RecurringSpec,
    capability: Capability,
    proposal: EntryPayload,
}

impl RecurringPlan {
    pub const MAGIC: &'static [u8] = b"FA-RECURRING\0";

    #[must_use]
    pub fn spec(&self) -> &RecurringSpec {
        &self.spec
    }

    pub fn proposal_digest(&self) -> Result<[u8; 32], KernelError> {
        Ok(self.proposal.proposal_digest()?)
    }

    pub fn encode(&self) -> Result<Vec<u8>, KernelError> {
        let mut w = Writer::new();
        w.fixed(Self::MAGIC)
            .u16(VERSION)
            .bytes(&self.proposal.clone().seal(Vec::new(), None)?.encode()?);
        Ok(w.finish()?)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, KernelError> {
        let bad = |e: fa_model::DecodeError| corrupt(e.to_string());
        let mut r = Reader::new(encoded);
        if r.fixed::<13>("recurring.plan_magic")
            .map_err(bad)?
            .as_slice()
            != Self::MAGIC
            || r.u16("recurring.plan_version").map_err(bad)? != VERSION
        {
            return Err(corrupt("unsupported recurring plan format"));
        }
        let entry = Entry::decode(r.bytes(MAX_BODY_BYTES * 2, "recurring.plan").map_err(bad)?)?;
        r.finish().map_err(bad)?;
        if !entry.approvals.is_empty() || entry.plan_certificate.is_some() {
            return Err(corrupt("a plan cannot carry an approval envelope"));
        }
        Self::from_proposal(entry.proposal)
    }

    fn from_proposal(original: EntryPayload) -> Result<Self, KernelError> {
        let body = extension(&original, RECURRING_SCHEDULE_EXTENSION)
            .ok_or_else(|| corrupt("plan has no recurring body"))?;
        let (spec, capability) = decode_body(body)?;
        let proposal = create_proposal(&spec, &capability)?;
        if proposal != original {
            return Err(corrupt("plan envelope differs from its canonical schedule"));
        }
        checked_spec(&spec, &capability).map_err(|r| corrupt(r.message))?;
        Ok(Self {
            spec,
            capability,
            proposal,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecurringRecorded {
    pub schedule: VId,
    pub control_entry: EntryRef,
    pub recorded_at: CommitSeq,
    pub already_recorded: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecurringView {
    pub schedule: VId,
    pub name: String,
    pub start: DateDay,
    pub end: Option<DateDay>,
    pub every_months: u32,
    pub month_end: MonthEndPolicy,
    pub principal: VId,
    pub created_at: CommitSeq,
    pub cancelled_at: Option<CommitSeq>,
    pub next_index: u64,
    pub next_date: Option<DateDay>,
    /// A cadence-law refusal (for example PreserveDay in a short month).
    pub blocked: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecurringBlocked {
    pub name: String,
    pub index: u64,
    pub date: DateDay,
    pub refusal: Refusal,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecurringBatch {
    pub tick: VId,
    pub posted: Vec<EntryRef>,
    pub blocked: Vec<RecurringBlocked>,
    /// True only for due work left by the batch bound, never just a blocked
    /// schedule. A caller can continue without an endless blocked loop.
    pub more: bool,
}

#[derive(Clone, Debug)]
struct Record {
    plan: RecurringPlan,
    creation: EntryRef,
    created_at: CommitSeq,
    cancelled_at: Option<CommitSeq>,
    next_index: u64,
}

/// Only this module constructs the posting token, after admitting the System
/// executor. It grants no accounting authority to the creator.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Executing {
    schedule: VId,
    index: u64,
    tick: Tick,
}

fn corrupt(why: impl Into<String>) -> KernelError {
    KernelError::Corrupt(format!("recurring schedule: {}", why.into()))
}

fn refusal(why: impl Into<String>) -> Refusal {
    Refusal::new(
        code::STRUCTURE,
        exit::USAGE,
        why,
        "plan §7.6 (approved fixed recurring effects and current execution authority)",
        "inspect `fa schedule recurring list --json`; create an approved monthly Original template, or cancel the blocked schedule",
    )
}

fn extension(p: &EntryPayload, tag: u16) -> Option<&[u8]> {
    p.extensions
        .iter()
        .find(|(t, _)| *t == tag)
        .map(|(_, b)| b.as_slice())
}

fn derive(domain: &[u8], parts: &[&[u8]]) -> VId {
    let digest = domain_digest(domain, parts);
    let mut low = [0; 16];
    low.copy_from_slice(&digest[..16]);
    VId(u128::from_le_bytes(low))
}

#[must_use]
pub fn recurring_schedule_vid(book: Id128, name: &str) -> VId {
    derive(b"fa:vid:recurring-schedule:v1", &[&book.0, name.as_bytes()])
}

#[must_use]
pub fn recurring_occurrence_vid(schedule: VId, index: u64) -> VId {
    derive(
        b"fa:vid:recurring:v1",
        &[&schedule.0.to_le_bytes(), &index.to_le_bytes()],
    )
}

fn cancel_vid(schedule: VId) -> VId {
    derive(b"fa:vid:recurring-cancel:v1", &[&schedule.0.to_le_bytes()])
}

fn policy_tag(policy: MonthEndPolicy) -> u8 {
    match policy {
        MonthEndPolicy::PreserveDay => 0,
        MonthEndPolicy::ClampToMonthEnd => 1,
        MonthEndPolicy::LastDayStaysLast => 2,
    }
}

fn encode_body(spec: &RecurringSpec, capability: &Capability) -> Result<Vec<u8>, KernelError> {
    let template = spec.template.clone().seal(Vec::new(), None)?.encode()?;
    let capability = capability
        .canonical_bytes()
        .map_err(|e| corrupt(e.to_string()))?;
    let mut w = Writer::new();
    w.u16(VERSION)
        .str(&spec.name)
        .u32(spec.every_months)
        .u8(policy_tag(spec.month_end))
        .opt(spec.end.as_ref(), |w, day| {
            w.i32(day.0);
        })
        .bytes(&template)
        .bytes(&capability);
    let bytes = w.finish()?;
    if bytes.len() > MAX_BODY_BYTES {
        return Err(corrupt("recurring body exceeds 32768 bytes"));
    }
    Ok(bytes)
}

fn decode_body(bytes: &[u8]) -> Result<(RecurringSpec, Capability), KernelError> {
    if bytes.len() > MAX_BODY_BYTES {
        return Err(corrupt("body exceeds its bound"));
    }
    let bad = |e: fa_model::DecodeError| corrupt(e.to_string());
    let mut r = Reader::new(bytes);
    if r.u16("recurring.version").map_err(bad)? != VERSION {
        return Err(corrupt("unsupported body version"));
    }
    let name = r
        .str(MAX_NAME_BYTES, "recurring.name")
        .map_err(bad)?
        .to_string();
    let every_months = r.u32("recurring.every_months").map_err(bad)?;
    let month_end = match r.u8("recurring.month_end").map_err(bad)? {
        0 => MonthEndPolicy::PreserveDay,
        1 => MonthEndPolicy::ClampToMonthEnd,
        2 => MonthEndPolicy::LastDayStaysLast,
        _ => return Err(corrupt("unknown month-end law")),
    };
    let end = r
        .opt("recurring.end", |r| Ok(DateDay(r.i32("recurring.end")?)))
        .map_err(bad)?;
    let template = Entry::decode(r.bytes(MAX_BODY_BYTES, "recurring.template").map_err(bad)?)?;
    if !template.approvals.is_empty() || template.plan_certificate.is_some() {
        return Err(corrupt("template carries an approval envelope"));
    }
    let capability = Capability::decode(
        r.bytes(MAX_BODY_BYTES, "recurring.capability")
            .map_err(bad)?,
    )
    .map_err(|e| corrupt(e.to_string()))?;
    r.finish().map_err(bad)?;
    Ok((
        RecurringSpec {
            name,
            template: template.proposal,
            every_months,
            month_end,
            end,
        },
        capability,
    ))
}

fn checked_spec(spec: &RecurringSpec, capability: &Capability) -> Result<(), Refusal> {
    let p = &spec.template;
    if spec.name.is_empty()
        || spec.name.len() > MAX_NAME_BYTES
        || spec.name.trim() != spec.name
        || spec.name.chars().any(char::is_control)
    {
        return Err(refusal(
            "a schedule name is 1..=128 bytes without surrounding whitespace or control characters",
        ));
    }
    if capability.profile() != Profile::Human
        || p.principal_ref != capability.holder()
        || p.branch_id != Id128::TRUNK
        || p.class != EntryClass::ORIGINAL
        || !matches!(p.origin, EntryOrigin::Intent { .. })
        || p.effective_period.is_some()
        || p.document_date.is_some()
        || p.session_ref.is_some()
        || p.pending.is_some()
        || !p.supersession.is_empty()
        || !p.extensions.is_empty()
        || !p.external_ids.is_empty()
        || p.base_totals.is_some()
        || p.legs
            .iter()
            .any(|leg| leg.base_amount.is_some() || !leg.settles.is_empty())
    {
        return Err(refusal(
            "monthly recurrence requires a Human-owned trunk Original template without fixed period, document date, session, pending, applications, supersession, extensions, external ids or base valuation",
        ));
    }
    p.validate().map_err(|e| refusal(e.to_string()))?;
    if p.unit_totals.iter().any(|sum| sum.debits != sum.credits) {
        return Err(refusal(
            "the recurring template is not balanced in every native unit",
        ));
    }
    if spec.end.is_some_and(|end| end < p.effective_date) {
        return Err(refusal("a recurring end date precedes its anchor"));
    }
    MonthlyRecurrence::new(p.effective_date, spec.every_months, spec.month_end)
        .map_err(|e| refusal(e.to_string()))?;
    Ok(())
}

fn create_proposal(
    spec: &RecurringSpec,
    capability: &Capability,
) -> Result<EntryPayload, KernelError> {
    let encoded = encode_body(spec, capability)?;
    let schedule = recurring_schedule_vid(spec.template.book_id, &spec.name);
    Ok(EntryPayload {
        schema_minor: fa_model::entry::EXTENSIONS_MINOR,
        book_id: spec.template.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::SCHEDULE_CONTROL,
        effective_date: DateDay::EPOCH,
        document_date: None,
        description: spec.template.description.clone(),
        effective_period: None,
        legs: Vec::new(),
        control: Some(ControlPayload::LifecycleTransition {
            object_ref: schedule,
            from: 0,
            to: ACTIVE as u8,
            proof_refs: Vec::new(),
            reason_code: 0,
        }),
        unit_totals: Vec::new(),
        base_totals: None,
        idempotency_key: domain_digest(b"fa:recurring-create-key:v1", &[&schedule.0.to_le_bytes()])
            .to_vec(),
        origin: EntryOrigin::Control {
            control_kind: ControlKind::RECURRING_SCHEDULE,
            spec_body_digest: domain_digest(b"fa:recurring-schedule:v1", &[&encoded]),
        },
        principal_ref: capability.holder(),
        session_ref: None,
        evidence: Vec::new(),
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: vec![(RECURRING_SCHEDULE_EXTENSION, encoded)],
        tags: Vec::new(),
    })
}

fn admit<V: Vfs + Clone>(
    db: &Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    write: bool,
) -> Outcome<()> {
    ctx.query().with_restriction(|| {
        // Whole-book scope is decided before reading any schedule or its template.
        if let Err(d) = fa_policy::admit_read(capability, capability.holder(), book.book_id)
            .and_then(|()| fa_policy::reach(capability, &Reach::whole_book(true), None))
        {
            return Ok(Err(policy::refusal(&d)));
        }
        if write
            && let Err(d) = fa_policy::admit(
                capability,
                &Intent {
                    principal: capability.holder(),
                    trunk: true,
                    op: Op::Post,
                    book: book.book_id,
                    legs: &[],
                },
            )
        {
            return Ok(Err(policy::refusal(&d)));
        }
        policy::current_at(db, book, capability).map(|r| r.map(|_| ()))
    })
}

pub fn plan_recurring<V: Vfs + Clone>(
    db: &Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    spec: RecurringSpec,
) -> Outcome<RecurringPlan> {
    ctx.query().with_restriction(|| {
        if let Err(r) = admit(db, ctx, book, capability, true)? {
            return Ok(Err(r));
        }
        if let Err(r) = checked_spec(&spec, capability) {
            return Ok(Err(r));
        }
        if spec.template.book_id != book.book_id {
            return Ok(Err(refusal("the recurring template names another book")));
        }
        if crate::schedule::book_policy(db)?.is_none() {
            return Ok(Err(refusal(
                "recurring schedules require the book's declared time_zone_policy",
            )));
        }
        let explicit: Vec<_> = spec
            .template
            .legs
            .iter()
            .map(|l| (l.amount.unit, l.amount.mantissa))
            .collect();
        if let Err(d) = fa_policy::admit(
            capability,
            &Intent {
                principal: capability.holder(),
                trunk: true,
                op: Op::Post,
                book: book.book_id,
                legs: &explicit,
            },
        ) {
            return Ok(Err(policy::refusal(&d)));
        }
        let proposal = create_proposal(&spec, capability)?;
        proposal.validate()?;
        Ok(Ok(RecurringPlan {
            spec,
            capability: capability.clone(),
            proposal,
        }))
    })
}

fn root_props(
    plan: &RecurringPlan,
    creation: VId,
    index: u64,
    cancelled: bool,
) -> Result<Vec<(fgdb_delta_types::PropertyKeyId, CanonicalScalar)>, KernelError> {
    let mut props = vec![
        (
            property::FA_PAYLOAD,
            scalar_bytes("recurring plan", plan.encode()?)?,
        ),
        (
            property::FA_DIGEST,
            scalar_bytes("recurring digest", plan.proposal_digest()?.to_vec())?,
        ),
        (
            property::BOOK_ID,
            scalar_bytes("recurring book", plan.spec.template.book_id.0.to_vec())?,
        ),
        (
            property::CODE,
            scalar_text("recurring name", &plan.spec.name)?,
        ),
        (
            property::TARGET_REF,
            scalar_bytes("recurring creation", creation.0.to_le_bytes().to_vec())?,
        ),
        (
            property::STATE,
            CanonicalScalar::Int(if cancelled { CANCELLED } else { ACTIVE }),
        ),
        (
            property::ORDINAL,
            CanonicalScalar::Int(
                i64::try_from(index).map_err(|_| corrupt("occurrence index exceeds i64"))?,
            ),
        ),
    ];
    props.sort_by_key(|(key, _)| key.0);
    Ok(props)
}

pub async fn create_recurring<V: Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    plan: RecurringPlan,
    approvals: Vec<ApprovalRef>,
) -> Outcome<RecurringRecorded> {
    if let Err(r) = admit(db, ctx, book, capability, true)? {
        return Ok(Err(r));
    }
    if plan.capability != *capability || plan.spec.template.book_id != book.book_id {
        return Ok(Err(refusal(
            "the approved schedule is bound to a different creator capability or book",
        )));
    }
    let rebuilt = match plan_recurring(db, ctx, book, capability, plan.spec.clone())? {
        Ok(plan) => plan,
        Err(r) => return Ok(Err(r)),
    };
    if rebuilt != plan {
        return Err(corrupt("the supplied plan differs from its bound body"));
    }
    let schedule = recurring_schedule_vid(book.book_id, &plan.spec.name);
    let evid = entry_vid(
        book.book_id,
        &capability.holder().0.to_le_bytes(),
        &plan.proposal.idempotency_key,
    );
    let mut txn = db.begin(&ctx.txn())?;
    if let Err(r) = policy::capability_witness(&txn, db, book, capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    if let Some(row) = txn.vertex(db, evid)? {
        txn.abort();
        let recorded = decode_entry(&row)?;
        if recorded.proposal != plan.proposal {
            return Ok(Err(conflict(
                "recurring creation identity",
                "name is already bound to another template",
            )));
        }
        return Ok(Ok(RecurringRecorded {
            schedule,
            control_entry: recorded.entry_ref(evid),
            recorded_at: row.created_at,
            already_recorded: true,
        }));
    }
    if txn.vertex(db, schedule)?.is_some() {
        txn.abort();
        return Ok(Err(conflict(
            "recurring schedule identity",
            "name already exists",
        )));
    }
    let epoch = policy::epoch_witness(&txn, db)?;
    let key = fa_policy::sod::control_key("ScheduleControl", None, "CreateRecurring");
    if policy::steward()?.preparer_op(&key) != Some(Op::Post) {
        txn.abort();
        return Err(corrupt("missing recurring creation authority row"));
    }
    if let Err(r) = policy::authorize_approvals(
        &txn,
        db,
        book,
        &approvals,
        &plan.proposal_digest()?,
        epoch,
        &key,
        0,
        Party {
            principal: capability.holder(),
            profile: capability.profile(),
        },
    )? {
        txn.abort();
        return Ok(Err(r));
    }
    let entry = plan.proposal.clone().seal(approvals, None)?;
    let mut stage = WriteBatch::new(relation::IN_CASE);
    stage.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    stage.create_vertex(
        schedule,
        vec![label::RECURRING_SCHEDULE],
        root_props(&plan, evid, 0, false)?,
    );
    stage.add_edge(
        edge_id(relation::IN_CASE, evid, schedule),
        evid,
        schedule,
        vec![],
    );
    txn.write(db, stage)?;
    finish(db, ctx, txn, schedule, entry.entry_ref(evid)).await
}

async fn finish<V: Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    mut txn: WriteTxn,
    schedule: VId,
    control_entry: EntryRef,
) -> Outcome<RecurringRecorded> {
    match txn.commit(db, &ctx.commit()).await {
        Ok(recorded_at) => Ok(Ok(RecurringRecorded {
            schedule,
            control_entry,
            recorded_at,
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(conflict("recurring lifecycle", detail)))
        }
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => Ok(Err(conflict(
            "recurring lifecycle identity",
            "another writer committed first; repeat the same request",
        ))),
        Err(e) => Err(e.into()),
    }
}

fn marker(p: &EntryPayload) -> Result<Option<(VId, u64, VId)>, KernelError> {
    let Some(bytes) = extension(p, RECURRING_OCCURRENCE_EXTENSION) else {
        return Ok(None);
    };
    let bad = |e: fa_model::DecodeError| corrupt(e.to_string());
    let mut r = Reader::new(bytes);
    if r.u16("occurrence.version").map_err(bad)? != VERSION {
        return Err(corrupt("unsupported occurrence version"));
    }
    let schedule = VId(r.u128("occurrence.schedule").map_err(bad)?);
    let index = r.u64("occurrence.index").map_err(bad)?;
    let tick = VId(r.u128("occurrence.tick").map_err(bad)?);
    r.finish().map_err(bad)?;
    Ok(Some((schedule, index, tick)))
}

fn occurrence(plan: &RecurringPlan, index: u64, tick: Tick) -> Result<EntryPayload, KernelError> {
    let spec = &plan.spec;
    let cadence = MonthlyRecurrence::new(
        spec.template.effective_date,
        spec.every_months,
        spec.month_end,
    )
    .map_err(|e| corrupt(e.to_string()))?;
    let date = cadence
        .occurrence(index)
        .map_err(|e| corrupt(e.to_string()))?
        .date;
    let schedule = recurring_schedule_vid(spec.template.book_id, &spec.name);
    let mut w = Writer::new();
    w.u16(VERSION)
        .u128(schedule.0)
        .u64(index)
        .u128(tick.entry.0);
    let mut p = spec.template.clone();
    p.schema_minor = fa_model::entry::EXTENSIONS_MINOR;
    p.effective_date = date;
    p.idempotency_key = domain_digest(
        b"fa:recurring-occurrence-key:v1",
        &[&schedule.0.to_le_bytes(), &index.to_le_bytes()],
    )
    .to_vec();
    p.origin = EntryOrigin::Schedule {
        schedule_ref: schedule,
        trigger: ScheduleTrigger::Sweep {
            tick_ref: tick.entry,
        },
    };
    p.extensions = vec![(RECURRING_OCCURRENCE_EXTENSION, w.finish()?)];
    Ok(p)
}

fn next_date(record: &Record) -> Result<Option<DateDay>, KernelError> {
    if record.cancelled_at.is_some() {
        return Ok(None);
    }
    let spec = &record.plan.spec;
    if let Some(end) = spec.end {
        // Do not ask PreserveDay to construct an invalid date in a month
        // beyond the inclusive end, or overflow an already completed cadence.
        let month_number = |date: DateDay| {
            i64::from(date.year())
                .checked_mul(12)
                .and_then(|year| year.checked_add(i64::from(date.month())))
                .ok_or_else(|| corrupt("month coordinate overflow"))
        };
        let last_month = month_number(end)?
            .checked_sub(month_number(spec.template.effective_date)?)
            .and_then(|months| u64::try_from(months).ok())
            .ok_or_else(|| corrupt("end month precedes the anchor"))?;
        if record.next_index > last_month / u64::from(spec.every_months) {
            return Ok(None);
        }
    }
    let date = MonthlyRecurrence::new(
        spec.template.effective_date,
        spec.every_months,
        spec.month_end,
    )
    .map_err(|e| corrupt(e.to_string()))?
    .occurrence(record.next_index)
    .map_err(|e| corrupt(e.to_string()))?
    .date;
    Ok((!spec.end.is_some_and(|end| date > end)).then_some(date))
}

/// Refold the immutable lifecycle and occurrence stream and compare every
/// mutable schedule row. No cache cursor can silently skip an occurrence.
fn records<V: Vfs + Clone>(
    db: &Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
) -> Result<BTreeMap<VId, Record>, KernelError> {
    ctx.query().with_restriction(|| {
        let mut records = BTreeMap::new();
        let mut roots = BTreeMap::new();
        let mut cancels = Vec::new();
        let mut occurrences = Vec::new();
        let at = db.frontier()?;
        for row in db.vertices_at(at)? {
            ctx.query().checkpoint().map_err(WriteTxnError::Interrupted)?;
            if row.labels.contains(&label::RECURRING_SCHEDULE) { roots.insert(row.vid, row.clone()); }
            if !row.labels.contains(&label::ENTRY) { continue; }
            let entry = decode_entry(&row)?;
            if let Some(mark) = marker(&entry.proposal)? { occurrences.push((row.clone(), entry.clone(), mark)); }
            if !matches!(entry.proposal.origin, EntryOrigin::Control { control_kind: ControlKind::RECURRING_SCHEDULE, .. }) { continue; }
            if entry.proposal.book_id != book.book_id || entry.proposal.branch_id != Id128::TRUNK
                || entry.proposal.class != EntryClass::SCHEDULE_CONTROL || entry_mirrors(&entry)? != row.props {
                return Err(corrupt("lifecycle record coordinate or mirrors differ"));
            }
            match &entry.proposal.control {
                Some(ControlPayload::LifecycleTransition { from: 0, to: 1, object_ref, .. }) => {
                    let plan = RecurringPlan::from_proposal(entry.proposal.clone())?;
                    let schedule = recurring_schedule_vid(book.book_id, &plan.spec.name);
                    let evid = entry_vid(book.book_id, &plan.capability.holder().0.to_le_bytes(), &plan.proposal.idempotency_key);
                    if *object_ref != schedule || row.vid != evid || entry.approvals.is_empty() {
                        return Err(corrupt("creation identity or bound approval missing"));
                    }
                    if records.insert(schedule, Record { plan, creation: entry.entry_ref(row.vid), created_at: row.created_at, cancelled_at: None, next_index: 0 }).is_some() {
                        return Err(corrupt("duplicate creation"));
                    }
                }
                Some(ControlPayload::ScheduleCancelled { schedule_ref, cause_ref }) => cancels.push((row.clone(), *schedule_ref, *cause_ref)),
                _ => return Err(corrupt("unknown recurring lifecycle transition")),
            }
        }
        for (row, schedule, cause) in cancels {
            let record = records.get_mut(&schedule).ok_or_else(|| corrupt("cancellation without creation"))?;
            if row.vid != cancel_vid(schedule) || cause != record.creation.vid || row.created_at <= record.created_at || record.cancelled_at.replace(row.created_at).is_some() {
                return Err(corrupt("invalid cancellation lineage"));
            }
        }
        let mut seen = BTreeSet::new();
        occurrences.sort_by_key(|(_, _, (schedule, index, _))| (*schedule, *index));
        for (row, entry, (schedule, index, tick_ref)) in occurrences {
            let record = records.get_mut(&schedule).ok_or_else(|| corrupt("occurrence without creation"))?;
            let tick_row = db.vertex_at(tick_ref, row.created_at)?.ok_or_else(|| corrupt("occurrence tick missing"))?;
            let tick_entry = decode_entry(&tick_row)?;
            let Some(ControlPayload::TimeTick { observed_utc_ns, monotonic_ok: true, .. }) = tick_entry.proposal.control else { return Err(corrupt("occurrence tick is not corroborated")); };
            let tick = Tick { observed_utc_ns, entry: tick_ref };
            if !seen.insert((schedule, index)) || index != record.next_index
                || row.vid != recurring_occurrence_vid(schedule, index)
                || entry_mirrors(&entry)? != row.props
                || row.created_at <= record.created_at || tick_row.created_at >= row.created_at
                || record.cancelled_at.is_some_and(|cancelled| row.created_at >= cancelled)
                || entry.proposal != occurrence(&record.plan, index, tick)? {
                return Err(corrupt("occurrence identity, order, timing or effects differ from the approved schedule"));
            }
            let time_policy = crate::schedule::book_policy(db)?.ok_or_else(|| corrupt("schedule book has no time-zone policy"))?;
            if entry.proposal.effective_date > time_policy.civil_date(observed_utc_ns)
                || record.plan.spec.end.is_some_and(|end| entry.proposal.effective_date > end) {
                return Err(corrupt("occurrence falls outside its tick or scheduled end"));
            }
            record.next_index = record.next_index.checked_add(1).ok_or_else(|| corrupt("occurrence count overflow"))?;
        }
        if roots.len() != records.len() { return Err(corrupt("schedule roots differ from immutable creations")); }
        for (schedule, record) in &records {
            let row = roots.get(schedule).ok_or_else(|| corrupt("missing schedule projection"))?;
            if row.props != root_props(&record.plan, record.creation.vid, record.next_index, record.cancelled_at.is_some())? {
                return Err(corrupt("schedule state or next occurrence differs from the journal fold"));
            }
        }
        Ok(records)
    })
}

/// Verify the recurring projection against the immutable journal. The caller
/// admits Verify/Read authority before this low-level whole-book operation.
pub fn verify_recurring<V: Vfs + Clone>(
    db: &Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
) -> Result<crate::schedule::ScheduleVerification, KernelError> {
    let mut verification = crate::schedule::ScheduleVerification::default();
    match records(db, ctx, book) {
        Ok(all) => {
            verification.schedules_checked = all.len();
            verification.executed = all.values().filter(|r| r.next_index > 0).count();
            verification.cancelled = all.values().filter(|r| r.cancelled_at.is_some()).count();
        }
        Err(KernelError::Corrupt(message)) => verification.drift.push(message),
        Err(error) => return Err(error),
    }
    Ok(verification)
}

pub fn recurring_schedules<V: Vfs + Clone>(
    db: &Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
) -> Outcome<Vec<RecurringView>> {
    if let Err(r) = admit(db, ctx, book, capability, false)? {
        return Ok(Err(r));
    }
    let mut out = Vec::new();
    for (schedule, record) in records(db, ctx, book)? {
        let spec = &record.plan.spec;
        let (next_date, blocked) = match next_date(&record) {
            Ok(date) => (date, None),
            Err(error) => (None, Some(error.to_string())),
        };
        out.push(RecurringView {
            schedule,
            name: spec.name.clone(),
            start: spec.template.effective_date,
            end: spec.end,
            every_months: spec.every_months,
            month_end: spec.month_end,
            principal: record.plan.capability.holder(),
            created_at: record.created_at,
            cancelled_at: record.cancelled_at,
            next_index: record.next_index,
            next_date,
            blocked,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(Ok(out))
}

pub async fn cancel_recurring<V: Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    name: &str,
    description: Erasable<String>,
) -> Outcome<RecurringRecorded> {
    if let Err(r) = admit(db, ctx, book, capability, true)? {
        return Ok(Err(r));
    }
    let schedule = recurring_schedule_vid(book.book_id, name);
    let Some(record) = records(db, ctx, book)?.remove(&schedule) else {
        return Ok(Err(refusal(format!(
            "no recurring schedule named `{name}`"
        ))));
    };
    if capability.holder() != record.plan.capability.holder()
        && let Err(d) = fa_policy::admit(
            capability,
            &Intent {
                principal: capability.holder(),
                trunk: true,
                op: Op::Approve,
                book: book.book_id,
                legs: &[],
            },
        )
    {
        return Ok(Err(policy::refusal(&d)));
    }
    let evid = cancel_vid(schedule);
    let mut txn = db.begin(&ctx.txn())?;
    if let Err(r) = policy::capability_witness(&txn, db, book, capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    let epoch = policy::epoch_witness(&txn, db)?;
    if let Some(row) = txn.vertex(db, evid)? {
        txn.abort();
        let entry = decode_entry(&row)?;
        return Ok(Ok(RecurringRecorded {
            schedule,
            control_entry: entry.entry_ref(evid),
            recorded_at: row.created_at,
            already_recorded: true,
        }));
    }
    if txn.vertex_property(db, schedule, property::STATE)? != Some(CanonicalScalar::Int(ACTIVE)) {
        txn.abort();
        return Ok(Err(conflict(
            "recurring cancellation",
            "schedule is no longer active",
        )));
    }
    let mut proposal = record.plan.proposal.clone();
    proposal.description = description;
    proposal.principal_ref = capability.holder();
    proposal.idempotency_key =
        domain_digest(b"fa:recurring-cancel-key:v1", &[&schedule.0.to_le_bytes()]).to_vec();
    proposal.extensions.clear();
    proposal.control = Some(ControlPayload::ScheduleCancelled {
        schedule_ref: schedule,
        cause_ref: record.creation.vid,
    });
    let key = fa_policy::sod::control_key("ScheduleControl", None, "CancelRecurring");
    if policy::steward()?.preparer_op(&key) != Some(Op::Post) {
        txn.abort();
        return Err(corrupt("missing recurring cancellation authority row"));
    }
    if let Err(r) = policy::authorize_approvals(
        &txn,
        db,
        book,
        &[],
        &proposal.proposal_digest()?,
        epoch,
        &key,
        0,
        Party {
            principal: capability.holder(),
            profile: capability.profile(),
        },
    )? {
        txn.abort();
        return Ok(Err(r));
    }
    let entry = proposal.seal(Vec::new(), None)?;
    let mut stage = WriteBatch::new(relation::IN_CASE);
    stage.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    stage.compare_and_set_vertex_property(
        schedule,
        property::STATE,
        Some(CanonicalScalar::Int(ACTIVE)),
        CanonicalScalar::Int(CANCELLED),
        WriteMismatchPolicy::AbortWrite,
    );
    stage.add_edge(
        edge_id(relation::IN_CASE, evid, schedule),
        evid,
        schedule,
        vec![],
    );
    txn.write(db, stage)?;
    finish(db, ctx, txn, schedule, entry.entry_ref(evid)).await
}

pub(crate) fn admission(
    p: &EntryPayload,
    execution: Option<Executing>,
) -> Result<Option<VId>, Refusal> {
    if extension(p, RECURRING_SCHEDULE_EXTENSION).is_some() {
        return Err(refusal(
            "a recurring schedule body belongs only to its approved creation control, never a posted entry",
        ));
    }
    let parsed = marker(p).map_err(|e| refusal(e.to_string()))?;
    match (parsed, execution) {
        (None, None) => Ok(None),
        (Some((schedule, index, tick)), Some(token))
            if schedule == token.schedule && index == token.index && tick == token.tick.entry =>
        {
            Ok(Some(recurring_occurrence_vid(schedule, index)))
        }
        _ => Err(refusal(
            "a recurring occurrence is minted only by the kernel under its approved schedule and committed tick",
        )),
    }
}

/// Native posting calls this after its ordinary capability witness and before
/// reading accounting data. Both schedule cancellation and a newer tick make
/// the transaction conflict; the complete effects must equal the bound body.
pub(crate) fn witness<V: Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    book: &BookContext,
    request: &PostRequest,
    token: Executing,
) -> Outcome<()> {
    let Some(root) = txn.vertex(db, token.schedule)? else {
        return Err(corrupt("executing schedule vanished"));
    };
    let plan = RecurringPlan::decode(&bytes(&root, property::FA_PAYLOAD, "recurring plan")?)?;
    if plan.spec.template.book_id != book.book_id
        || plan.capability != request.capability
        || recurring_schedule_vid(book.book_id, &plan.spec.name) != token.schedule
    {
        return Err(corrupt("executing schedule or capability differs"));
    }
    if txn.vertex_property(db, token.schedule, property::STATE)?
        != Some(CanonicalScalar::Int(ACTIVE))
        || txn.vertex_property(db, token.schedule, property::ORDINAL)?
            != Some(CanonicalScalar::Int(
                i64::try_from(token.index).map_err(|_| corrupt("index overflow"))?,
            ))
    {
        return Ok(Err(conflict(
            "recurring occurrence",
            "schedule was cancelled or another sweep advanced it",
        )));
    }
    let (_, latest) = crate::sweep::tick_witness(txn, db)?;
    if latest != Some(token.tick) {
        return Ok(Err(conflict(
            "recurring tick",
            "the committed tick changed",
        )));
    }
    let Some(tick_row) = txn.vertex(db, token.tick.entry)? else {
        return Err(corrupt("executing tick vanished"));
    };
    if !crate::sweep::tick_corroborated(&tick_row)? {
        return Ok(Err(crate::sweep::uncorroborated(token.tick)));
    }
    let time_policy =
        crate::schedule::book_policy(db)?.ok_or_else(|| corrupt("missing time-zone policy"))?;
    if request.proposal != occurrence(&plan, token.index, token.tick)?
        || request.proposal.effective_date > time_policy.civil_date(token.tick.observed_utc_ns)
        || plan
            .spec
            .end
            .is_some_and(|end| request.proposal.effective_date > end)
    {
        return Ok(Err(refusal(
            "the occurrence differs from its approved effects, date, or end bound",
        )));
    }
    Ok(Ok(()))
}

pub(crate) fn stage_progress<V: Vfs + Clone>(
    txn: &mut WriteTxn,
    db: &mut Database<V>,
    token: Executing,
    entry: VId,
) -> Result<(), KernelError> {
    let before = i64::try_from(token.index).map_err(|_| corrupt("index overflow"))?;
    let after = before
        .checked_add(1)
        .ok_or_else(|| corrupt("index overflow"))?;
    let mut stage = WriteBatch::new(relation::IN_CASE);
    stage.compare_and_set_vertex_property(
        token.schedule,
        property::ORDINAL,
        Some(CanonicalScalar::Int(before)),
        CanonicalScalar::Int(after),
        WriteMismatchPolicy::AbortWrite,
    );
    stage.add_edge(
        edge_id(relation::IN_CASE, entry, token.schedule),
        entry,
        token.schedule,
        vec![],
    );
    txn.write(db, stage)?;
    Ok(())
}

/// At most max_batch successful occurrences, each an atomic ordinary post plus schedule
/// advancement. A refused occurrence stays due, is reported with its schedule,
/// and does not prevent another schedule from running.
pub async fn sweep_recurring_batch<V: Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    req: &SweepRequest,
) -> Outcome<Option<RecurringBatch>> {
    let key = fa_policy::sod::control_key("SweepControl", None, "Recurring");
    if let Err(d) = fa_policy::reach(&req.capability, &Reach::whole_book(true), None) {
        return Ok(Err(policy::refusal(&d)));
    }
    if let Err(r) = ctx
        .query()
        .with_restriction(|| crate::sweep::admit_sweep(db, book, req, &key))?
    {
        return Ok(Err(r));
    }
    if let Err(r) = crate::scratch::ensure_history(db, ctx).await? {
        return Ok(Err(r));
    }
    let Some(tick) = ctx
        .query()
        .with_restriction(|| crate::sweep::latest_tick(db))?
    else {
        return Ok(Ok(None));
    };
    if let Err(r) = ctx
        .query()
        .with_restriction(|| crate::sweep::corroborated_at_head(db, tick))?
    {
        return Ok(Err(r));
    }
    let Some(time_policy) = ctx
        .query()
        .with_restriction(|| crate::schedule::book_policy(db))?
    else {
        return Ok(Ok(None));
    };
    let today = time_policy.civil_date(tick.observed_utc_ns);
    let mut batch = RecurringBatch {
        tick: tick.entry,
        posted: Vec::new(),
        blocked: Vec::new(),
        more: false,
    };
    let all = records(db, ctx, book)?;
    for (schedule, mut record) in all {
        loop {
            let date = match next_date(&record) {
                Ok(Some(date)) if date <= today => date,
                Ok(_) => break,
                Err(error) => {
                    batch.blocked.push(RecurringBlocked {
                        name: record.plan.spec.name.clone(),
                        index: record.next_index,
                        date: record.plan.spec.template.effective_date,
                        refusal: refusal(error.to_string()),
                    });
                    break;
                }
            };
            if batch.posted.len() >= req.max_batch {
                batch.more = true;
                break;
            }
            let token = Executing {
                schedule,
                index: record.next_index,
                tick,
            };
            let request = PostRequest {
                proposal: occurrence(&record.plan, record.next_index, tick)?,
                approvals: Vec::new(),
                capability: record.plan.capability.clone(),
                plan_certificate: None,
            };
            let preparation = crate::post::prepare_recurring(db, ctx, book, request, token)?;
            let result = match preparation {
                Err(r) => Err(r),
                Ok(PostPreparation::AlreadyRecorded(posted)) => Ok(posted),
                Ok(PostPreparation::Ready(prepared)) => {
                    if let Err(r) = crate::post::witness_recurring_executor(
                        &prepared,
                        db,
                        book,
                        &req.capability,
                    )? {
                        prepared.abort();
                        Err(r)
                    } else if let Err(d) = fa_policy::current(&req.capability, db.frontier()?) {
                        prepared.abort();
                        Err(policy::refusal(&d))
                    } else {
                        prepared.commit(db, ctx).await?
                    }
                }
            };
            match result {
                Ok(posted) => {
                    batch.posted.push(posted.entry_ref());
                    record.next_index = record
                        .next_index
                        .checked_add(1)
                        .ok_or_else(|| corrupt("index overflow"))?;
                }
                Err(r) => {
                    batch.blocked.push(RecurringBlocked {
                        name: record.plan.spec.name.clone(),
                        index: record.next_index,
                        date,
                        refusal: r,
                    });
                    break;
                }
            }
        }
    }
    if batch.posted.is_empty() && batch.blocked.is_empty() && !batch.more {
        Ok(Ok(None))
    } else {
        Ok(Ok(Some(batch)))
    }
}
