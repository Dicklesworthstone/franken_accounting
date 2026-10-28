//! One reviewed, indivisible Reversal/Replacement operation in a draft.
//!
//! V5 retains both complete V3 members in one Plan record. Publication uses
//! the native pair preparation and commit protocol, including its original
//! witnesses and capacity checks; a Replacement never enters PostBatch's
//! independently executable member protocol.

use super::*;
use crate::batch::{
    BatchPosted, OutcomeBody, StagedBatch, TemplateByteTracker, batch_byte_budget_refusal,
    outcome_vid, request_digest, stage_outcome_tracked,
};
use crate::post::{PostPreparation, PostRequest, PreparedPost, prepare_replacement_pair_admitted};
use fa_model::SupersessionKind;

pub(super) const CORRECTION_VERSION: u16 = 5;

fn shape(reversal: &PostIntent, replacement: &PostIntent) -> bool {
    let first = reversal.proposal();
    let last = replacement.proposal();
    matches!(
        (first.supersession.as_slice(), last.supersession.as_slice()),
        ([rev], [rep])
            if first.class == EntryClass::REVERSAL
                && last.class == EntryClass::REPLACEMENT
                && rev.kind == SupersessionKind::Reverses
                && rep.kind == SupersessionKind::Replaces
                && rev.target == rep.target
                && first.book_id == last.book_id
                && first.branch_id == Id128::TRUNK
                && last.branch_id == Id128::TRUNK
                && first.principal_ref == last.principal_ref
                && first.idempotency_key != last.idempotency_key
    )
}

fn record_bytes(members: &[Vec<u8>; 2]) -> Result<Vec<u8>, KernelError> {
    let mut w = Writer::new();
    w.u16(CORRECTION_VERSION)
        .bytes(&members[0])
        .bytes(&members[1]);
    Ok(w.finish()?)
}

pub(super) fn decode_record(bytes: &[u8]) -> Result<batch::DecodedPlanRecord, KernelError> {
    if bytes.len() > fa_model::limits::MAX_EXTENSION_BYTES {
        return Err(KernelError::Corrupt(
            "oversized draft correction record".into(),
        ));
    }
    let mut r = Reader::new(bytes);
    if r.u16("draft_correction.version").map_err(decode)? != CORRECTION_VERSION {
        return Err(KernelError::Corrupt(
            "unsupported draft correction version".into(),
        ));
    }
    let encoded = [
        r.bytes(
            fa_model::limits::MAX_EXTENSION_BYTES,
            "draft_correction.reversal",
        )
        .map_err(decode)?
        .to_vec(),
        r.bytes(
            fa_model::limits::MAX_EXTENSION_BYTES,
            "draft_correction.replacement",
        )
        .map_err(decode)?
        .to_vec(),
    ];
    r.finish().map_err(decode)?;
    let mut members = Vec::with_capacity(2);
    for bytes in &encoded {
        let member = decode_intent(bytes)?;
        if member.3.is_none()
            || intent_bytes(&member.0, &member.1, member.2, member.3.as_ref())? != *bytes
        {
            return Err(KernelError::Corrupt(
                "a draft correction member lacks its canonical reviewed Entry".into(),
            ));
        }
        members.push(member);
    }
    if !shape(&members[0].0, &members[1].0)
        || members[0].1 != members[1].1
        || members[0].1.holder() != members[0].0.proposal().principal_ref
        || record_bytes(&encoded)? != bytes
    {
        return Err(KernelError::Corrupt(
            "a draft correction must bind one ordered pair, target and planner".into(),
        ));
    }
    Ok(batch::DecodedPlanRecord {
        kind: Kind::PlanCorrection,
        discriminator: members[0].0.proposal().idempotency_key.clone(),
        members,
    })
}

pub(super) fn is_correction(view: &DraftView) -> bool {
    view.intents
        .iter()
        .any(|member| member.intent.proposal().class == EntryClass::REPLACEMENT)
}

/// Ordinary records cannot contain Replacement, so its presence identifies
/// the V5 operation. One draft owns exactly that one atomic record.
pub(super) fn validate_view(view: &DraftView) -> Result<(), KernelError> {
    if !is_correction(view) {
        return Ok(());
    }
    let [first, last] = view.intents.as_slice() else {
        return Err(KernelError::Corrupt(
            "a correction draft contains exactly one complete pair".into(),
        ));
    };
    if first.record != last.record
        || first.recorded_at != last.recorded_at
        || first.capability != last.capability
        || first.capability.holder() != view.body.owner
        || first.intent.proposal().book_id != view.body.book_id
        || first.resolved_entry.is_none()
        || last.resolved_entry.is_none()
        || !shape(&first.intent, &last.intent)
    {
        return Err(KernelError::Corrupt(
            "a correction draft has mixed or incomplete operation membership".into(),
        ));
    }
    Ok(())
}

pub(super) fn dedicated() -> Refusal {
    usage(
        "a correction draft holds one indivisible reversal and replacement; nothing was appended",
        "open an empty draft for the complete correction pair; plan other operations into separate drafts",
    )
}

enum Execution {
    Batch(Box<StagedBatch>),
    Correction(Box<PreparedPost>),
}

/// The lifecycle layer operates on either complete native execution protocol.
/// Both expose their original transaction, never independently committable
/// correction members.
pub(super) struct StagedDraft {
    execution: Execution,
    pub(super) outcome: VId,
    pub(super) entries: Vec<EntryRef>,
    pub(super) periods: Vec<String>,
    prepared: Vec<Entry>,
}

impl StagedDraft {
    pub(super) fn txn(&self) -> &WriteTxn {
        match &self.execution {
            Execution::Batch(staged) => &staged.txn,
            Execution::Correction(prepared) => prepared.transaction(),
        }
    }

    pub(super) fn parts(
        &mut self,
    ) -> Result<(&mut WriteTxn, &mut TemplateByteTracker), KernelError> {
        match &mut self.execution {
            Execution::Batch(staged) => Ok((&mut staged.txn, &mut staged.template_tracker)),
            Execution::Correction(prepared) => prepared.pair_transaction_parts(),
        }
    }

    pub(super) fn abort(self) {
        match self.execution {
            Execution::Batch(staged) => staged.txn.abort(),
            Execution::Correction(prepared) => prepared.abort(),
        }
    }

    pub(super) async fn commit<V: asupersync::fs::Vfs + Clone>(
        self,
        db: &mut Database<V>,
        ctx: &PurposeContexts,
        book: &BookContext,
        capabilities: &[Capability],
        batch: &PostBatch,
        admission: Admission,
    ) -> Outcome<BatchPosted> {
        match self.execution {
            Execution::Batch(staged) => {
                commit_batch(db, ctx, book, capabilities, batch, admission, staged).await
            }
            Execution::Correction(mut prepared) => {
                let (_, tracker) = prepared.pair_transaction_parts()?;
                if tracker.total_bytes() > fa_model::limits::MAX_BATCH_TEMPLATE_BYTES {
                    let refusal = batch_byte_budget_refusal(tracker.total_bytes(), Some(1), 2);
                    prepared.abort();
                    return Ok(Err(refusal));
                }
                let posted = match prepared.commit(db, ctx).await? {
                    Ok(posted) => posted,
                    Err(refusal) => return Ok(Err(refusal)),
                };
                if !matches!(posted, crate::post::Posted::Committed { .. }) {
                    return Err(KernelError::Corrupt(
                        "a prepared draft correction returned a partial recorded outcome".into(),
                    ));
                }
                Ok(Ok(BatchPosted {
                    outcome: self.outcome,
                    entries: self.entries,
                    periods: self.periods,
                    recorded_at: posted.recorded_at(),
                    already_recorded: false,
                }))
            }
        }
    }
}

fn request(intent: &PostIntent, capability: &Capability) -> PostRequest {
    PostRequest {
        proposal: intent.proposal().clone(),
        approvals: intent.approvals().to_vec(),
        capability: capability.clone(),
        plan_certificate: None,
    }
}

pub(super) fn stage<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capabilities: &[Capability],
    batch: &PostBatch,
    admission: Admission,
    correction: bool,
) -> Outcome<StagedDraft> {
    if !correction {
        return match stage_batch(db, ctx, book, capabilities, batch, admission)? {
            Err(refusal) => Ok(Err(refusal)),
            Ok(BatchStage::Recorded(_)) => Err(KernelError::Corrupt(
                "an open draft already has its promotion outcome".into(),
            )),
            Ok(BatchStage::Staged(staged)) => Ok(Ok(StagedDraft {
                outcome: staged.outcome,
                entries: staged.entries.clone(),
                periods: staged.periods.clone(),
                prepared: staged.prepared_entries().to_vec(),
                execution: Execution::Batch(staged),
            })),
        };
    }
    if !matches!(
        admission,
        Admission::Plan | Admission::Promote(_) | Admission::ScratchDraft(_)
    ) || capabilities.len() != 2
        || capabilities[0] != capabilities[1]
        || batch.members().len() != 2
        || !shape(&batch.members()[0], &batch.members()[1])
        || capabilities[0].holder() != batch.principal()
    {
        return Err(KernelError::Corrupt(
            "a correction draft stages only its complete admitted pair".into(),
        ));
    }
    if batch
        .members()
        .iter()
        .any(|member| member.proposal().idempotency_key == batch.idempotency_key())
    {
        return Ok(Err(crate::outcome::key_conflict()));
    }
    let (prior, prepared) = match prepare_replacement_pair_admitted(
        db,
        ctx,
        book,
        request(&batch.members()[0], &capabilities[0]),
        request(&batch.members()[1], &capabilities[1]),
        admission,
    )? {
        Ok(prepared) => prepared,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let PostPreparation::Ready(mut prepared) = prepared else {
        return Ok(Err(Refusal::new(
            code::IDEMPOTENCY_CONFLICT,
            exit::CONFLICT,
            "this correction pair is already posted outside the open draft; nothing was published",
            "plan §15.2 (promotion commits new reviewed effects atomically)",
            "discard the obsolete draft and inspect the recorded correction",
        )));
    };
    if prior.is_some() {
        prepared.abort();
        return Err(KernelError::Corrupt(
            "a new correction cannot reuse only its reversal".into(),
        ));
    }
    let entries = prepared
        .paired_refs()
        .ok_or_else(|| {
            KernelError::Corrupt("a draft correction preparation lost its reversal".into())
        })?
        .to_vec();
    let (first, period) = prepared.paired_entry().ok_or_else(|| {
        KernelError::Corrupt("a draft correction preparation lost its reversal".into())
    })?;
    let periods = vec![period.to_string(), prepared.period().to_string()];
    let resolved = vec![first.clone(), prepared.entry().clone()];
    let outcome = outcome_vid(book, batch);
    let body = OutcomeBody {
        request_digest: request_digest(
            batch.idempotency_key(),
            &entries.iter().map(|entry| entry.vid).collect::<Vec<_>>(),
        ),
        entries: entries.clone(),
    };
    let (txn, tracker) = prepared.pair_transaction_parts()?;
    let legacy = entry_vid(
        book.book_id,
        &batch.principal().0.to_le_bytes(),
        batch.idempotency_key(),
    );
    if txn.vertex(db, outcome)?.is_some() || txn.vertex(db, legacy)?.is_some() {
        prepared.abort();
        return Ok(Err(crate::outcome::key_conflict()));
    }
    if let Err(refusal) = crate::outcome::require_unused_legacy_key(txn, db, book, outcome)? {
        prepared.abort();
        return Ok(Err(refusal));
    }
    let mut writes = WriteBatch::new(relation::IN_BATCH);
    stage_outcome_tracked(
        &ctx.query(),
        &mut writes,
        tracker,
        book.book_id,
        outcome,
        &body,
    )?;
    for entry in &entries {
        tracker.add_edge(relation::IN_BATCH, &[]);
        writes.add_edge(
            edge_id(relation::IN_BATCH, entry.vid, outcome),
            entry.vid,
            outcome,
            vec![],
        );
    }
    if tracker.total_bytes() > fa_model::limits::MAX_BATCH_TEMPLATE_BYTES {
        let refusal = batch_byte_budget_refusal(tracker.total_bytes(), Some(1), 2);
        prepared.abort();
        return Ok(Err(refusal));
    }
    txn.write_ordered(db, vec![writes])?;
    Ok(Ok(StagedDraft {
        outcome,
        entries,
        periods,
        prepared: resolved,
        execution: Execution::Correction(prepared),
    }))
}

async fn preview_pair<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    view: &DraftView,
    members: Vec<PostIntent>,
    capabilities: Vec<Capability>,
) -> Outcome<DraftPreview> {
    let batch = PostBatch::new(promotion_key(view.vid), members).map_err(intent_error)?;
    for (member, capability) in batch.members().iter().zip(&capabilities) {
        if let Err(d) = fa_policy::reach(capability, &fa_policy::Reach::whole_book(true), None) {
            return Ok(Err(denial(&d)));
        }
        if let Err(refusal) =
            crate::post::authorize_request(db, book, &request(member, capability), Admission::Plan)?
        {
            return Ok(Err(refusal));
        }
    }
    if let Err(refusal) = crate::scratch::ensure_history(db, ctx).await? {
        return Ok(Err(refusal));
    }
    let staged = match stage(db, ctx, book, &capabilities, &batch, Admission::Plan, true)? {
        Ok(staged) => staged,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if !view.intents.is_empty()
        && let Err(refusal) =
            check_resolved_members(&view.body.name, &view.intents, &staged.entries)
    {
        staged.abort();
        return Ok(Err(refusal));
    }
    let members = batch
        .members()
        .iter()
        .zip(&capabilities)
        .zip(&staged.prepared)
        .zip(&staged.periods)
        .map(|(((intent, capability), entry), period)| {
            Ok(DraftPreviewMember {
                intent: intent.clone(),
                capability_commitment: capability.commitment().map_err(|error| {
                    KernelError::Corrupt(format!("draft correction capability: {error}"))
                })?,
                entry: entry.clone(),
                period: period.clone(),
            })
        })
        .collect::<Result<Vec<_>, KernelError>>()?;
    let preview = DraftPreview {
        draft: view.vid,
        principal: view.body.owner,
        snapshot_seq: staged.txn().basis(),
        members,
        effects_digest: staged.txn().staged_effect_digest()?.0,
    };
    staged.abort();
    Ok(Ok(preview))
}

pub(super) async fn preview<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    view: &DraftView,
) -> Outcome<DraftPreview> {
    validate_view(view)?;
    preview_pair(
        db,
        ctx,
        book,
        view,
        view.intents
            .iter()
            .map(|member| member.intent.clone())
            .collect(),
        view.intents
            .iter()
            .map(|member| member.capability.clone())
            .collect(),
    )
    .await
}

/// Retain one complete correction pair in an empty draft. The target must
/// already be committed; the native pair pipeline validates its exact inverse,
/// the replacement's newly declared applications, and both approval envelopes.
/// Identical retries return the original Plan even after discard or promotion.
#[allow(clippy::too_many_arguments)]
pub async fn plan_correction_into_draft<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    name: &str,
    reversal: PostIntent,
    replacement: PostIntent,
    req: DraftRequest,
) -> Outcome<DraftPlanned> {
    if !shape(&reversal, &replacement) || reversal.proposal().book_id != book.book_id {
        return Ok(Err(usage(
            "a draft correction requires one Reversal and one Replacement of the same committed target, book and planner",
            "supply the complete correction pair with distinct member keys",
        )));
    }
    if reversal.proposal().principal_ref != req.capability.holder() {
        return Ok(Err(denial(&Denial::NotHolder {
            holder: req.capability.holder(),
            principal: reversal.proposal().principal_ref,
        })));
    }
    let view = match owned_draft(db, ctx, book, &req.capability, name)? {
        Ok(view) => view,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let mut proposal = record_proposal(
        book,
        &view.body,
        Kind::PlanCorrection,
        view.body.owner,
        &reversal.proposal().idempotency_key,
        &req,
        Vec::new(),
        Vec::new(),
    )?;
    let evid = record_vid(book, &proposal);
    let retained: Vec<_> = view
        .intents
        .iter()
        .filter(|member| member.record == evid)
        .collect();
    let requested = [reversal, replacement];
    if !retained.is_empty() {
        let mut same = retained.len() == 2;
        for (old, new) in retained.iter().zip(&requested) {
            same &= batch::same_member(book, old, new, &req.capability)?;
        }
        if !same {
            let row = db.vertex(evid)?.ok_or_else(|| {
                KernelError::Corrupt("a draft correction record disappeared".into())
            })?;
            return Ok(Err(conflict_with(&row)));
        }
        return Ok(Ok(DraftPlanned {
            recorded: DraftRecorded {
                draft: view.vid,
                control_entry: evid,
                recorded_at: retained[0].recorded_at,
                already_recorded: true,
            },
            plan: None,
        }));
    }
    if view.state != DraftState::Open {
        return Ok(Err(not_open(&view.body, view.state)));
    }
    if !view.intents.is_empty() {
        return Ok(Err(dedicated()));
    }
    if db.vertex(evid)?.is_some() {
        return Err(KernelError::Corrupt(
            "a correction Plan is absent from its draft log".into(),
        ));
    }
    let preview = match preview_pair(
        db,
        ctx,
        book,
        &view,
        requested.to_vec(),
        vec![req.capability.clone(); 2],
    )
    .await?
    {
        Ok(preview) => preview,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let encode = |index: usize| {
        let member = &preview.members()[index];
        intent_bytes(
            &member.intent,
            &req.capability,
            Some(member.entry.entry_digest),
            Some(&member.entry),
        )
    };
    let extension = record_bytes(&[encode(0)?, encode(1)?])?;
    if extension.len() > fa_model::limits::MAX_EXTENSION_BYTES {
        return Ok(Err(usage(
            "the complete reviewed correction exceeds max_extension_bytes; nothing was appended",
            "reduce retained input size while keeping both correction members together",
        )));
    }
    proposal.extensions = vec![(fa_model::entry::DRAFT_INTENT_EXTENSION, extension)];
    if proposal.validate().is_err() {
        return Ok(Err(usage(
            "the complete reviewed correction exceeds the DraftControl format; nothing was appended",
            "reduce retained input size while keeping both correction members together",
        )));
    }
    let mut txn = db.begin(&ctx.txn())?;
    if let Err(refusal) = capability_witness(&txn, db, book, &req.capability)? {
        txn.abort();
        return Ok(Err(refusal));
    }
    if let Err(refusal) = witness_open(&txn, db, book, name)? {
        txn.abort();
        return Ok(Err(refusal));
    }
    if let Err(refusal) = witness_membership(&txn, db, book, &view)? {
        txn.abort();
        return Ok(Err(refusal));
    }
    let entry = proposal.clone().seal(Vec::new(), None)?;
    let mut writes = WriteBatch::new(relation::IN_CASE);
    writes.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    writes.add_edge(
        edge_id(relation::IN_CASE, evid, view.vid),
        evid,
        view.vid,
        vec![],
    );
    if let Err(refusal) = batch::storage_admission(
        txn.write(db, writes).map(Ok).map_err(KernelError::from),
        evid,
    )? {
        txn.abort();
        return Ok(Err(refusal));
    }
    Ok(batch::storage_admission(
        finish(db, ctx, book, txn, &proposal, view.vid, evid).await,
        evid,
    )?
    .map(|recorded| DraftPlanned {
        plan: (!recorded.already_recorded).then_some(preview),
        recorded,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fa_model::Supersession;

    fn members() -> [PostIntent; 2] {
        let original = super::super::tests::codec_intent();
        let target = EntryRef {
            vid: VId(99),
            entry_digest: [7; 32],
        };
        let mut reversal = original.proposal().clone();
        reversal.class = EntryClass::REVERSAL;
        reversal.idempotency_key = b"reverse".to_vec();
        reversal.supersession = vec![Supersession {
            target,
            kind: SupersessionKind::Reverses,
            reason_code: 1,
        }];
        for leg in &mut reversal.legs {
            leg.side = leg.side.flipped();
        }
        reversal.unit_totals = EntryPayload::fold_unit_totals(&reversal.legs).unwrap();
        let mut replacement = original.proposal().clone();
        replacement.class = EntryClass::REPLACEMENT;
        replacement.idempotency_key = b"replace".to_vec();
        replacement.supersession = vec![Supersession {
            target,
            kind: SupersessionKind::Replaces,
            reason_code: 1,
        }];
        [
            PostIntent::new(reversal, Vec::new()).unwrap(),
            PostIntent::new(replacement, Vec::new()).unwrap(),
        ]
    }

    #[test]
    fn correction_codec_preserves_one_pair_and_rejects_partial_or_ordinary_transport() {
        let members = members();
        let capability = Capability::embedded(VId(7), &["post"]).unwrap();
        let encode = |member: &PostIntent, capability: &Capability| {
            let entry = member.proposal().clone().seal(Vec::new(), None).unwrap();
            intent_bytes(member, capability, Some(entry.entry_digest), Some(&entry)).unwrap()
        };
        let encoded = [
            encode(&members[0], &capability),
            encode(&members[1], &capability),
        ];
        let bytes = record_bytes(&encoded).unwrap();
        let decoded = batch::decode_plan_record(&bytes).unwrap();
        assert!(matches!(decoded.kind, Kind::PlanCorrection));
        assert_eq!(decoded.discriminator, b"reverse");
        assert_eq!(decoded.members[0].0, members[0]);
        assert_eq!(decoded.members[1].0, members[1]);
        for end in 0..bytes.len() {
            assert!(batch::decode_plan_record(&bytes[..end]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(batch::decode_plan_record(&trailing).is_err());
        assert!(
            batch::decode_plan_record(
                &record_bytes(&[encoded[1].clone(), encoded[0].clone()]).unwrap()
            )
            .is_err()
        );
        let different = Capability::embedded(VId(8), &["post"]).unwrap();
        assert!(
            batch::decode_plan_record(
                &record_bytes(&[encoded[0].clone(), encode(&members[1], &different)]).unwrap()
            )
            .is_err()
        );
        // A retained Replacement is not a single member or ordinary batch.
        assert!(batch::decode_plan_record(&encoded[1]).is_err());
        let mut w = Writer::new();
        w.u16(4).bytes(b"ordinary").list(&encoded, |w, bytes| {
            w.bytes(bytes);
        });
        assert!(batch::decode_plan_record(&w.finish().unwrap()).is_err());
    }
}
