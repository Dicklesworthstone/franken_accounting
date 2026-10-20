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
use fa_intents::PostBatch;
use fa_model::symbols::{label, property, relation};
use fa_model::{EntryRef, Reader, Writer, intent_outcome_vid};
use fa_policy::Capability;
use fgdb::{Database, VertexRow, WriteBatch, WriteTxn, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::genesis::BookContext;
use crate::policy;
use crate::post::{Admission, BatchMember, PostPreparation, PostRequest, prepare_member};
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::edge_id;

const OUTCOME_MAGIC: &[u8; 11] = b"FA-OUTCOME\0";
const OUTCOME_MAJOR: u16 = 1;
const OUTCOME_MINOR: u16 = 0;
/// The outcome kind of a committed PostBatch.
const KIND_BATCH: u8 = 1;

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
    vid: VId,
) -> Result<Option<(OutcomeBody, CommitSeq)>, KernelError> {
    db.vertex(vid)?.map(|row| outcome_of(&row)).transpose()
}

fn outcome_of(row: &VertexRow) -> Result<(OutcomeBody, CommitSeq), KernelError> {
    if !row.labels.contains(&label::INTENT_OUTCOME) {
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
    let bytes = bytes.as_slice();
    Ok((OutcomeBody::decode(bytes)?, row.created_at))
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
    let Some((body, recorded_at)) = read_outcome(db, outcome)? else {
        return Err(KernelError::Corrupt(
            "an intent outcome vanished between two reads".into(),
        ));
    };
    let mut entries = Vec::with_capacity(batch.members().len());
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
            Ok(PostPreparation::AlreadyRecorded(posted)) => entries.push(posted.entry_ref()),
            Ok(PostPreparation::Ready(prepared)) => {
                prepared.abort();
                return Ok(Err(outcome_conflict(outcome)));
            }
        }
    }
    let vids: Vec<VId> = entries.iter().map(|e| e.vid).collect();
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
    let ovid = outcome_vid(book, batch);
    let mut txn: Option<WriteTxn> = None;
    let mut members: Vec<BatchMember> = Vec::with_capacity(batch.members().len());
    for (i, (intent, capability)) in batch.members().iter().zip(capabilities).enumerate() {
        let request = member_request(intent, capability);
        let prepared = match prepare_member(db, ctx, book, request, admission, txn.take())? {
            Err(refusal) => return Ok(Err(member_refusal(i, refusal))),
            // The member's identity is taken. Admission already ran for it,
            // so the outcome may be observed: with a recorded outcome this is
            // the identical retry or a conflict; without one, the member was
            // posted outside any batch.
            Ok(PostPreparation::AlreadyRecorded(posted)) => {
                if db.vertex(ovid)?.is_some() {
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
        let (staged, member) = prepared.into_member()?;
        // After the first member's admission, the outcome identity is a
        // witness: absent here, and a concurrent identical batch conflicts.
        // A recorded outcome whose first member is new is another request.
        if i == 0 && staged.vertex(db, ovid)?.is_some() {
            staged.abort();
            return Ok(Err(outcome_conflict(ovid)));
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
    stage.create_vertex(
        ovid,
        vec![label::INTENT_OUTCOME],
        vec![(
            property::FA_PAYLOAD,
            CanonicalScalar::bytes(body.canonical_bytes()?).map_err(|e| {
                KernelError::Corrupt(format!("intent outcome payload scalar: {e:?}"))
            })?,
        )],
    );
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
    let StagedBatch {
        mut txn,
        outcome: ovid,
        entries,
        periods,
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
        )) => match db.vertex(ovid)? {
            Some(_) => judge_retry(db, ctx, book, capabilities, batch, admission, ovid),
            None => Ok(Err(Refusal::new(
                code::IDEMPOTENCY_CONFLICT,
                exit::CONFLICT,
                "a member's identity was taken by a concurrent commit; nothing in the batch was recorded",
                "plan §4.9 (identities are derived, first committer wins)",
                "retry the identical batch: a member recorded outside it is then named",
            ))),
        },
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
