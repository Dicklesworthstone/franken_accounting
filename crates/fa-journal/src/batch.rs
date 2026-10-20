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

use asupersync::fs::Vfs;
use fa_intents::{BatchPlan, BatchPlanCertificate, PostBatch};
use fa_model::symbols::{label, property, relation};
use fa_model::{
    Entry, EntryClass, EntryRef, Id128, Reader, Writer, entry_mirrors, intent_outcome_vid,
};
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

fn stage_outcome(
    cx: &QueryCx,
    stage: &mut WriteBatch,
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
    for (i, (intent, capability)) in batch.members().iter().zip(capabilities).enumerate() {
        match prepare_member(
            db,
            ctx,
            book,
            member_request(intent, capability),
            admission,
            None,
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
    for (index, intent) in batch.members().iter().enumerate() {
        if let Err(refusal) = crate::post::authorize_request(
            db,
            book,
            &member_request(intent, &capability),
            Admission::Commit,
        )? {
            return Ok(Err(member_refusal(index, refusal)));
        }
    }
    ctx.query()
        .checkpoint()
        .map_err(WriteTxnError::Interrupted)?;
    if let Err(refusal) = crate::scratch::ensure_history(db, ctx).await? {
        return Ok(Err(refusal));
    }
    let capabilities = vec![capability; batch.members().len()];
    let staged = match stage_batch(db, ctx, book, &capabilities, &batch, Admission::Commit)? {
        Err(refusal) => return Ok(Err(refusal)),
        Ok(BatchStage::Recorded(posted)) => return Ok(Ok(posted)),
        Ok(BatchStage::Staged(staged)) => staged,
    };
    commit_batch(
        db,
        ctx,
        book,
        &capabilities,
        &batch,
        Admission::Commit,
        staged,
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
    prepared: Vec<Entry>,
    security_policy_epoch: u64,
    /// A rehearsal can be retained and inspected, but never published.
    planning: bool,
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
    ctx.txn().checkpoint().map_err(WriteTxnError::Interrupted)?;
    if capabilities.len() != batch.members().len() {
        return Err(KernelError::Corrupt(
            "a batch is staged with one capability per member".into(),
        ));
    }
    if let Some((i, member)) = batch
        .members()
        .iter()
        .enumerate()
        .find(|(_, m)| !batchable(m.proposal().class))
    {
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
    let mut txn: Option<WriteTxn> = None;
    let mut members: Vec<BatchMember> = Vec::with_capacity(batch.members().len());
    let mut resolved = Vec::with_capacity(batch.members().len());
    let mut security_policy_epoch = None;
    let planning = matches!(admission, Admission::Plan);
    for (i, (intent, capability)) in batch.members().iter().zip(capabilities).enumerate() {
        let request = member_request(intent, capability);
        let prepared = match prepare_member(db, ctx, book, request, admission, txn.take())? {
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
        let (staged, member) = prepared.into_member(planning)?;
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
    let vids: Vec<VId> = members.iter().map(|m| m.entry_ref.vid).collect();
    let body = OutcomeBody {
        request_digest: request_digest(batch.idempotency_key(), &vids),
        entries: members.iter().map(|m| m.entry_ref).collect(),
    };
    let mut stage = WriteBatch::new(relation::IN_BATCH);
    stage_outcome(&ctx.query(), &mut stage, book.book_id, ovid, &body)?;
    for m in &members {
        let evid = m.entry_ref.vid;
        stage.add_edge(edge_id(relation::IN_BATCH, evid, ovid), evid, ovid, vec![]);
    }
    txn.write_ordered(db, vec![stage])?;
    Ok(Ok(BatchStage::Staged(Box::new(StagedBatch {
        txn,
        outcome: ovid,
        entries: body.entries,
        periods: members.into_iter().map(|m| m.period).collect(),
        prepared: resolved,
        security_policy_epoch: security_policy_epoch.ok_or_else(|| {
            KernelError::Corrupt("a validated batch has no security policy epoch".into())
        })?,
        planning,
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
    if staged.planning || matches!(admission, Admission::Plan) {
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
        ..
    } = *staged;
    let commit = ctx.commit();
    commit.checkpoint().map_err(WriteTxnError::Interrupted)?;
    for capability in capabilities {
        if let Err(d) = fa_policy::current(capability, db.frontier()?) {
            txn.abort();
            return Ok(Err(policy::refusal(&d)));
        }
    }
    match txn.commit(db, &commit).await {
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
    for (index, intent) in batch.members().iter().enumerate() {
        if let Err(refusal) = crate::post::authorize_request(
            db,
            book,
            &member_request(intent, capability),
            admission,
        )? {
            return Ok(Err(member_refusal(index, refusal)));
        }
    }
    Ok(Ok(()))
}

fn plan_retention(
    ctx: &PurposeContexts,
    book: &BookContext,
    plan: &BatchPlan,
    entries: &[EntryRef],
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
    retention.create_vertex(
        cvid,
        vec![label::CERTIFICATE],
        vec![
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
        ],
    );
    for vid in entries
        .iter()
        .map(|entry| entry.vid)
        .chain([outcome_vid(book, plan.batch())])
    {
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
    let plan = BatchPlan::new(
        batch,
        staged.prepared.clone(),
        staged.periods.clone(),
        certificate,
    )
    .map_err(plan_codec)?;
    staged
        .txn
        .write_ordered(db, vec![plan_retention(ctx, book, &plan, &staged.entries)?])?;
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
            || entry.props != entry_mirrors(prepared)?
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
    staged
        .txn
        .write_ordered(db, vec![plan_retention(ctx, book, &plan, &staged.entries)?])?;
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
mod tests {
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
}
