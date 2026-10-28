//! Exact, atomic draft review in an owned memory database (plan §15.2).
//!
//! The complete native source history is checked before maintenance filtering.
//! A reviewer supplies current read authority, never a substitute planner or
//! promoter. Every hypothetical member retains its original capability and
//! approval references and runs through the same carried transaction as a real
//! promotion. Only this factory can construct the scratch admission token.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_model::{Entry, EntryRef};
use fgdb::{Database, MemVfs};
use fgdb_delta_types::{DeltaRow, ElementId};
use fgdb_types::{CommitSeq, EId};

use super::*;
use crate::batch::BatchPosted;
use crate::scratch::SeqMap;

const SOURCE_FORMAT: &[u8] = b"fa:draft-rehearsal-source:v1";
const SOURCE_DOMAIN: &[u8] = b"fa:draft-rehearsal-source-digest:v1";
const MAX_SOURCE_BYTES: usize = 1024 + (fa_model::limits::MAX_BATCH_ENTRIES + 1) * 56;

/// Only `rehearse_draft_into` constructs this token, after taking ownership of
/// an empty MemVfs target and validating/replaying the exact source prefix.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Rehearsing(());

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DraftRehearsalRequest {
    pub name: String,
    /// A captured trunk prefix, never an implicit moving head.
    pub known_at: CommitSeq,
}

/// An original immutable control entry and its native publication position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DraftSourceRecord {
    pub entry_ref: EntryRef,
    pub recorded_at: CommitSeq,
}

impl DraftSourceRecord {
    fn encode(&self, w: &mut Writer) {
        self.entry_ref.encode(w);
        w.u64(self.recorded_at.0);
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, fa_model::DecodeError> {
        Ok(Self {
            entry_ref: EntryRef::decode(r)?,
            recorded_at: CommitSeq(r.u64("draft_source.recorded_at")?),
        })
    }
}

/// Complete source identity of one open draft at a selected trunk prefix.
/// Each Plan EntryRef binds the exact retained intent and capability bytes.
/// Container decoding is not historical verification; the factory refolds
/// original native entries and checks every DraftSet/membership mirror.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DraftRehearsalSource {
    pub known_at: CommitSeq,
    pub body: DraftBody,
    pub open: DraftSourceRecord,
    pub plans: Vec<DraftSourceRecord>,
}

fn corrupt(message: impl Into<String>) -> KernelError {
    KernelError::Corrupt(format!("draft rehearsal: {}", message.into()))
}

impl DraftRehearsalSource {
    fn check(&self) -> Result<(), KernelError> {
        check_name(&self.body.name).map_err(|r| corrupt(r.message))?;
        if self.open.recorded_at.0 == 0
            || self.open.recorded_at > self.known_at
            || self.plans.is_empty()
            || self.plans.len() > fa_model::limits::MAX_BATCH_ENTRIES
        {
            return Err(corrupt(
                "source record count or coordinate is out of bounds",
            ));
        }
        let mut previous = self.open.recorded_at;
        let mut identities = BTreeSet::from([self.open.entry_ref.vid]);
        for plan in &self.plans {
            if plan.recorded_at <= previous
                || plan.recorded_at > self.known_at
                || !identities.insert(plan.entry_ref.vid)
            {
                return Err(corrupt("source Plan records are not distinct and ordered"));
            }
            previous = plan.recorded_at;
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, KernelError> {
        self.check()?;
        let mut w = Writer::new();
        w.bytes(SOURCE_FORMAT)
            .u64(self.known_at.0)
            .bytes(&self.body.canonical_bytes()?);
        self.open.encode(&mut w);
        w.list(&self.plans, |w, record| record.encode(w));
        let bytes = w.finish().map_err(|e| KernelError::Model(e.into()))?;
        if bytes.len() > MAX_SOURCE_BYTES {
            return Err(corrupt("source witness exceeds its bounded format"));
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, KernelError> {
        if bytes.len() > MAX_SOURCE_BYTES {
            return Err(corrupt("source witness exceeds its bounded format"));
        }
        let mut r = Reader::new(bytes);
        if r.bytes(64, "draft_source.format").map_err(super::decode)? != SOURCE_FORMAT {
            return Err(corrupt("unsupported source witness format"));
        }
        let known_at = CommitSeq(r.u64("draft_source.known_at").map_err(super::decode)?);
        let body = DraftBody::decode(
            r.bytes(MAX_DRAFT_NAME_BYTES + 64, "draft_source.body")
                .map_err(super::decode)?,
        )?;
        let open = DraftSourceRecord::decode(&mut r).map_err(super::decode)?;
        let plans = r
            .list(
                fa_model::limits::MAX_BATCH_ENTRIES,
                "draft_source.plans",
                DraftSourceRecord::decode,
            )
            .map_err(super::decode)?;
        r.finish().map_err(super::decode)?;
        let source = Self {
            known_at,
            body,
            open,
            plans,
        };
        if source.canonical_bytes()?.as_slice() != bytes {
            return Err(corrupt("noncanonical source witness"));
        }
        Ok(source)
    }

    pub fn digest(&self) -> Result<[u8; 32], KernelError> {
        Ok(domain_digest(SOURCE_DOMAIN, &[&self.canonical_bytes()?]))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DraftRehearsal {
    pub source: DraftRehearsalSource,
    pub view: DraftView,
    pub seq_map: SeqMap,
    /// A single fresh hypothetical publication, never a trunk promotion.
    pub batch: BatchPosted,
}

fn checkpoint(cx: &PurposeContexts) -> Result<(), KernelError> {
    cx.query()
        .checkpoint()
        .map_err(WriteTxnError::Interrupted)?;
    Ok(())
}

struct Record {
    reference: DraftSourceRecord,
    entry: Entry,
}

fn open_props(
    body: &DraftBody,
) -> Result<Vec<(fgdb_delta_types::PropertyKeyId, CanonicalScalar)>, KernelError> {
    let mut props = vec![
        (
            property::FA_PAYLOAD,
            scalar_bytes("draft._fa_payload", body.canonical_bytes()?)?,
        ),
        (
            property::FA_DIGEST,
            scalar_bytes("draft._fa_digest", body.digest()?.to_vec())?,
        ),
        (
            property::BOOK_ID,
            scalar_bytes("book_id", body.book_id.0.to_vec())?,
        ),
        (property::CODE, scalar_text("draft.code", &body.name)?),
        (property::STATE, DraftState::Open.scalar()),
    ];
    props.sort_by_key(|(key, _)| key.0);
    Ok(props)
}

fn selected_history_exists<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    draft: VId,
    at: CommitSeq,
) -> Result<bool, KernelError> {
    for batch in db.delta_since(CommitSeq(0))? {
        if batch.commit_seq() > at {
            break;
        }
        for coordinate in batch.coordinate_entries() {
            for delta in &coordinate.rows {
                checkpoint(cx)?;
                if matches!(delta, DeltaRow::CreateVertex { vid, .. } if *vid == draft)
                    || matches!(delta, DeltaRow::CreateEdge { dst, .. }
                        if coordinate.relation == relation::IN_CASE && *dst == draft)
                {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

/// Validate the selected open DraftSet and every membership against their
/// actual births. A removed/rewritten edge or a later restoration is damage,
/// even when a maintenance label would hide it from the replay filter.
fn verify_mirrors<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    source: &DraftRehearsalSource,
) -> Result<(), KernelError> {
    let draft = source.body.vid();
    let at = source.known_at;
    let expected_props = open_props(&source.body)?;
    let expected_edges: BTreeMap<EId, &DraftSourceRecord> = std::iter::once(&source.open)
        .chain(&source.plans)
        .map(|record| {
            (
                edge_id(relation::IN_CASE, record.entry_ref.vid, draft),
                record,
            )
        })
        .collect();
    let control_vids: BTreeSet<_> = std::iter::once(&source.open)
        .chain(&source.plans)
        .map(|record| record.entry_ref.vid)
        .collect();
    let mut born = None;
    let mut edge_births = BTreeSet::new();
    for batch in db.delta_since(CommitSeq(0))? {
        let seq = batch.commit_seq();
        if seq > at {
            break;
        }
        for coordinate in batch.coordinate_entries() {
            for delta in &coordinate.rows {
                checkpoint(cx)?;
                match delta {
                    DeltaRow::CreateVertex {
                        vid,
                        labels,
                        props,
                        birth_ordinal,
                        valid_time,
                        ..
                    } if *vid == draft => {
                        if born.replace(*birth_ordinal).is_some()
                            || seq != source.open.recorded_at
                            || coordinate.relation != relation::IN_CASE
                            || labels.as_slice() != [label::DRAFT_SET]
                            || props != &expected_props
                            || valid_time.is_some()
                        {
                            return Err(corrupt("DraftSet differs from its canonical Open birth"));
                        }
                    }
                    DeltaRow::Property {
                        elem: ElementId::Vertex(vid),
                        ..
                    }
                    | DeltaRow::LabelMembership { vid, .. }
                    | DeltaRow::DeleteVertex { vid, .. }
                        if *vid == draft =>
                    {
                        return Err(corrupt(
                            "an open DraftSet was modified after its native birth",
                        ));
                    }
                    DeltaRow::CreateEdge {
                        eid,
                        src,
                        relation: edge_relation,
                        dst,
                        props,
                        canonical_key,
                        valid_time,
                        ..
                    } if expected_edges.contains_key(eid)
                        || (coordinate.relation == relation::IN_CASE
                            && (*dst == draft || *src == draft || control_vids.contains(src))) =>
                    {
                        let Some(record) = expected_edges.get(eid) else {
                            return Err(corrupt("unexpected DraftSet membership edge"));
                        };
                        if coordinate.relation != relation::IN_CASE
                            || *edge_relation != relation::IN_CASE
                            || *src != record.entry_ref.vid
                            || *dst != draft
                            || seq != record.recorded_at
                            || !props.is_empty()
                            || canonical_key.is_some()
                            || valid_time.is_some()
                            || !edge_births.insert(*eid)
                        {
                            return Err(corrupt(
                                "draft membership differs from its control publication",
                            ));
                        }
                    }
                    DeltaRow::Property {
                        elem: ElementId::Edge(eid),
                        ..
                    }
                    | DeltaRow::DeleteEdge { eid, .. }
                        if expected_edges.contains_key(eid) =>
                    {
                        return Err(corrupt("immutable draft membership was modified"));
                    }
                    DeltaRow::ValidTime { elem, .. }
                        if matches!(elem, ElementId::Vertex(vid) if *vid == draft)
                            || matches!(elem, ElementId::Edge(eid) if expected_edges.contains_key(eid)) =>
                    {
                        return Err(corrupt("draft source acquired valid-time history"));
                    }
                    _ => {}
                }
            }
        }
    }
    let row = db
        .vertex_at(draft, at)?
        .map(|row| row.seen_at(at))
        .ok_or_else(|| corrupt("the original DraftSet is absent at the selected prefix"))?;
    if born != Some(row.birth_ordinal)
        || row.created_at != source.open.recorded_at
        || row.retired_at.is_some()
        || row.labels.as_slice() != [label::DRAFT_SET]
        || row.props != expected_props
        || edge_births.len() != expected_edges.len()
    {
        return Err(corrupt(
            "DraftSet or its complete membership disagrees with native history",
        ));
    }
    let mut live = BTreeSet::new();
    for edge in db.edges_at(at)? {
        let entry = &edge.entry;
        if expected_edges.contains_key(&entry.eid)
            || (entry.relation == relation::IN_CASE
                && (entry.dst == draft || entry.src == draft || control_vids.contains(&entry.src)))
        {
            let Some(record) = expected_edges.get(&entry.eid) else {
                return Err(corrupt("unrecorded live DraftSet membership"));
            };
            if entry.relation != relation::IN_CASE
                || entry.src != record.entry_ref.vid
                || entry.dst != draft
                || entry.created_at != record.recorded_at
                || entry.retired_at.is_some_and(|retired| retired <= at)
                || !edge.props.is_empty()
                || !live.insert(entry.eid)
            {
                return Err(corrupt(
                    "live draft membership differs from its original control",
                ));
            }
        }
    }
    if live != edge_births {
        return Err(corrupt("an original draft membership edge is missing"));
    }
    Ok(())
}

fn capture<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    request: &DraftRehearsalRequest,
) -> Outcome<(DraftRehearsalSource, DraftView)> {
    crate::entry_history::verify_entry_history(db, cx, book, Some(request.known_at))?;
    let draft = draft_vid(book.book_id, &request.name);
    let mut records = Vec::new();
    for row in db.vertices_at(request.known_at)? {
        checkpoint(cx)?;
        if !row.labels.contains(&label::ENTRY) {
            continue;
        }
        let (entry, recorded_at) = crate::post::entry_of(&row)?;
        if matches!(&entry.proposal.control,
            Some(ControlPayload::LifecycleTransition { object_ref, .. }) if *object_ref == draft)
        {
            if entry.proposal.class != EntryClass::DRAFT_CONTROL {
                return Err(corrupt(
                    "a foreign control class names the selected DraftSet",
                ));
            }
            records.push(Record {
                reference: DraftSourceRecord {
                    entry_ref: entry.entry_ref(row.vid),
                    recorded_at,
                },
                entry,
            });
        }
    }
    records.sort_by_key(|record| (record.reference.recorded_at, record.reference.entry_ref.vid));
    let Some(first) = records.first() else {
        if db.vertex_at(draft, request.known_at)?.is_some()
            || selected_history_exists(db, cx, draft, request.known_at)?
        {
            return Err(corrupt("DraftSet history has no original Open entry"));
        }
        return Ok(Err(unknown(&request.name)));
    };
    let [(tag, body_bytes)] = first.entry.proposal.extensions.as_slice() else {
        return Err(corrupt("the first draft control has no sole Open body"));
    };
    if *tag != fa_model::entry::DRAFT_BODY_EXTENSION {
        return Err(corrupt("the first draft control is not Open"));
    }
    let body = DraftBody::decode(body_bytes)?;
    if body.book_id != book.book_id
        || body.name != request.name
        || body.vid() != draft
        || body.canonical_bytes()? != *body_bytes
    {
        return Err(corrupt("Open body identifies another draft"));
    }
    let body_digest = body.digest()?;
    let mut state = None;
    let mut previous = CommitSeq(0);
    let mut intents = Vec::new();
    let mut plans = Vec::new();
    let mut member_keys = BTreeSet::new();
    for record in &records {
        checkpoint(cx)?;
        let proposal = &record.entry.proposal;
        let Some(ControlPayload::LifecycleTransition {
            from,
            to,
            proof_refs,
            reason_code,
            ..
        }) = &proposal.control
        else {
            return Err(corrupt("draft control lacks its lifecycle transition"));
        };
        if record.reference.recorded_at <= previous
            || proposal.origin
                != (EntryOrigin::Control {
                    control_kind: ControlKind::DRAFT_TRANSITION,
                    spec_body_digest: body_digest,
                })
            || !proposal.legs.is_empty()
            || !record.entry.approvals.is_empty()
            || record.entry.plan_certificate.is_some()
            || *reason_code != 0
        {
            return Err(corrupt(
                "draft control does not match its native lifecycle contract",
            ));
        }
        let mut plan_discriminator = None;
        let kind = match (state, *from, *to) {
            (None, 0, 1) => {
                if proposal.principal_ref != body.owner
                    || proposal.extensions.as_slice() != first.entry.proposal.extensions.as_slice()
                    || !proof_refs.is_empty()
                {
                    return Err(corrupt("Open record does not bind its owner and body"));
                }
                state = Some(DraftState::Open);
                Kind::Open
            }
            (Some(DraftState::Open), 1, 1) => {
                let [(tag, bytes)] = proposal.extensions.as_slice() else {
                    return Err(corrupt("Plan record lacks its sole retained intent"));
                };
                if *tag != fa_model::entry::DRAFT_INTENT_EXTENSION || !proof_refs.is_empty() {
                    return Err(corrupt(
                        "Plan record carries a different extension or proof",
                    ));
                }
                let decoded = decode_plan_record(bytes)?;
                for (intent, capability, resolved_entry_digest, resolved_entry) in decoded.members {
                    let planned = intent.proposal();
                    if proposal.principal_ref != body.owner
                        || capability.holder() != body.owner
                        || planned.principal_ref != body.owner
                        || planned.book_id != book.book_id
                        || planned.branch_id != Id128::TRUNK
                        || !member_keys.insert(planned.idempotency_key.clone())
                        || member_keys.len() > fa_model::limits::MAX_BATCH_ENTRIES
                    {
                        return Err(corrupt(
                            "Plan record does not bind its original owner, intent and capability",
                        ));
                    }
                    intents.push(PlannedIntent {
                        record: record.reference.entry_ref.vid,
                        recorded_at: record.reference.recorded_at,
                        intent,
                        capability,
                        resolved_entry_digest,
                        resolved_entry,
                    });
                }
                plans.push(record.reference.clone());
                plan_discriminator = Some(decoded.discriminator);
                decoded.kind
            }
            (Some(DraftState::Open), 1, 2) => {
                state = Some(DraftState::Promoted);
                Kind::Promote
            }
            (Some(DraftState::Open), 1, 3) => {
                state = Some(DraftState::Discarded);
                Kind::Discard
            }
            _ => return Err(corrupt("draft controls do not form one lawful lifecycle")),
        };
        let discriminator = plan_discriminator.as_deref().unwrap_or(&[]);
        if proposal.idempotency_key != record_key(kind, draft, discriminator)
            || record.reference.entry_ref.vid != record_vid(book, proposal)
        {
            return Err(corrupt(
                "draft control identity differs from its canonical native identity",
            ));
        }
        previous = record.reference.recorded_at;
    }
    let state = state.ok_or_else(|| corrupt("draft has no Open lifecycle"))?;
    if state != DraftState::Open {
        return Ok(Err(not_open(&body, state)));
    }
    if intents.is_empty() {
        return Ok(Err(usage(
            format!("draft `{}` has no planned intent to rehearse", request.name),
            "plan intents into the draft before reviewing its accounting effects",
        )));
    }
    let source = DraftRehearsalSource {
        known_at: request.known_at,
        body: body.clone(),
        open: first.reference.clone(),
        plans,
    };
    source.check()?;
    verify_mirrors(db, cx, &source)?;
    let view = DraftView {
        vid: draft,
        body,
        state,
        opened_at: source.open.recorded_at,
        intents,
        closed: None,
    };
    correction::validate_view(&view)?;
    Ok(Ok((source, view)))
}

/// Rehearse every retained plan in one atomic publication in an owned, empty
/// memory database. Current whole-book read admission precedes source/target
/// observation. The selected source is immutable history; later changes do
/// not enter it. No source write, promotion record, approval or grant is made.
pub async fn rehearse_draft_into<V: Vfs + Clone>(
    source: &mut Database<V>,
    mut target: Database<MemVfs>,
    cx: &PurposeContexts,
    book: &BookContext,
    reviewer: &Capability,
    request: DraftRehearsalRequest,
) -> Outcome<(Database<MemVfs>, DraftRehearsal)> {
    let admitted = match crate::policy::admit_reads(source, book, reviewer.holder(), reviewer)? {
        Ok(admitted) => admitted,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if let Err(refusal) = admitted.whole_book(request.known_at) {
        return Ok(Err(refusal));
    }
    if let Err(refusal) = check_name(&request.name) {
        return Ok(Err(refusal));
    }
    if request.known_at.0 == 0 || request.known_at > source.frontier()? {
        return Ok(Err(usage(
            "a draft rehearsal selects a nonzero recorded source prefix",
            "select the captured current head or an earlier retained draft prefix",
        )));
    }
    if target.frontier()? != CommitSeq(0) || !target.vertices_at(CommitSeq(0))?.is_empty() {
        return Ok(Err(usage(
            "a draft rehearsal requires an empty memory database at sequence zero",
            "create a fresh open_memory database for this rehearsal",
        )));
    }
    if let Err(refusal) = crate::scratch::ensure_history(source, cx).await? {
        return Ok(Err(refusal));
    }
    let (witness, view) = match capture(source, cx, book, &request)? {
        Ok(captured) => captured,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let seq_map = match crate::scratch::replay_into_preserving_publications(
        source,
        &mut target,
        cx,
        book,
        request.known_at,
    )
    .await?
    {
        Ok(map) => map,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let (copied_source, copied_view) = match capture(&target, cx, book, &request)? {
        Ok(captured) => captured,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if copied_source != witness || copied_view != view || target.frontier()? != request.known_at {
        return Err(corrupt(
            "scratch replay differs from the complete original draft source",
        ));
    }
    let members = view
        .intents
        .iter()
        .map(|plan| plan.intent.clone())
        .collect();
    let capabilities: Vec<_> = view
        .intents
        .iter()
        .map(|plan| plan.capability.clone())
        .collect();
    let batch = PostBatch::new(promotion_key(view.vid), members).map_err(intent_error)?;
    let admission = Admission::ScratchDraft(Rehearsing(()));
    let staged = match correction::stage(
        &mut target,
        cx,
        book,
        &capabilities,
        &batch,
        admission,
        correction::is_correction(&view),
    )? {
        Ok(staged) => staged,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if let Err(refusal) = check_resolved_members(&request.name, &view.intents, &staged.entries) {
        staged.abort();
        return Ok(Err(refusal));
    }
    if let Err(refusal) = witness_open(staged.txn(), &target, book, &request.name)? {
        staged.abort();
        return Ok(Err(refusal));
    }
    if let Err(refusal) = witness_membership(staged.txn(), &target, book, &view)? {
        staged.abort();
        return Ok(Err(refusal));
    }
    let posted = match staged
        .commit(&mut target, cx, book, &capabilities, &batch, admission)
        .await?
    {
        Ok(posted) => posted,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if posted.already_recorded || request.known_at.0.checked_add(1) != Some(posted.recorded_at.0) {
        return Err(corrupt(
            "draft rehearsal was not one fresh atomic publication",
        ));
    }
    Ok(Ok((
        target,
        DraftRehearsal {
            source: witness,
            view,
            seq_map,
            batch: posted,
        },
    )))
}
