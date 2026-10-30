//! Atomic additions to an ordered draft. One Plan record binds the complete
//! batch, so neither publication nor replay can expose only some members.

use super::*;

const BATCH_VERSION: u16 = 4;

pub(super) struct DecodedPlanRecord {
    pub(super) kind: Kind,
    pub(super) discriminator: Vec<u8>,
    pub(super) members: Vec<DecodedIntent>,
}

fn batch_bytes(key: &[u8], members: &[Vec<u8>]) -> Result<Vec<u8>, KernelError> {
    let mut w = Writer::new();
    w.u16(BATCH_VERSION).bytes(key).list(members, |w, bytes| {
        w.bytes(bytes);
    });
    Ok(w.finish()?)
}

/// V1--V3 retain their original single-intent interpretation. V4 contains a
/// batch key and an ordered list of complete V3 intents, including the exact
/// reviewed entries. The outer record is the publication/identity boundary.
pub(super) fn decode_plan_record(bytes: &[u8]) -> Result<DecodedPlanRecord, KernelError> {
    if bytes.get(..2) == Some(correction::CORRECTION_VERSION.to_le_bytes().as_slice()) {
        return correction::decode_record(bytes);
    }
    if bytes.get(..2) != Some(BATCH_VERSION.to_le_bytes().as_slice()) {
        let member = decode_intent(bytes)?;
        if member.0.proposal().class == EntryClass::REPLACEMENT {
            return Err(KernelError::Corrupt(
                "a draft Replacement requires its complete correction record".into(),
            ));
        }
        if intent_bytes(&member.0, &member.1, member.2, member.3.as_ref())? != bytes {
            return Err(KernelError::Corrupt("noncanonical draft intent".into()));
        }
        return Ok(DecodedPlanRecord {
            kind: Kind::Plan,
            discriminator: member.0.proposal().idempotency_key.clone(),
            members: vec![member],
        });
    }
    if bytes.len() > fa_model::limits::MAX_EXTENSION_BYTES {
        return Err(KernelError::Corrupt(
            "oversized draft batch extension".into(),
        ));
    }
    let mut r = Reader::new(bytes);
    r.u16("draft_batch.version").map_err(decode)?;
    let key = r
        .bytes(
            fa_model::limits::MAX_IDEMPOTENCY_KEY_BYTES,
            "draft_batch.key",
        )
        .map_err(decode)?
        .to_vec();
    let encoded = r
        .list(
            fa_model::limits::MAX_BATCH_ENTRIES,
            "draft_batch.members",
            |r| {
                Ok(
                    r.bytes(fa_model::limits::MAX_EXTENSION_BYTES, "draft_batch.member")?
                        .to_vec(),
                )
            },
        )
        .map_err(decode)?;
    r.finish().map_err(decode)?;
    let mut members = Vec::with_capacity(encoded.len());
    for bytes in &encoded {
        let member = decode_intent(bytes)?;
        if member.0.proposal().class == EntryClass::REPLACEMENT
            || member.3.is_none()
            || intent_bytes(&member.0, &member.1, member.2, member.3.as_ref())? != *bytes
        {
            return Err(KernelError::Corrupt(
                "a draft batch member lacks its canonical reviewed Entry".into(),
            ));
        }
        members.push(member);
    }
    // Reuse the public batch shape law: nonempty, bounded, common principal,
    // book and branch, and distinct member keys. No different interpretation
    // of a PostBatch is introduced by its draft transport.
    let batch = PostBatch::new(
        key.clone(),
        members.iter().map(|member| member.0.clone()).collect(),
    )
    .map_err(intent_error)?;
    let first = &members[0].1;
    if members.iter().any(|member| &member.1 != first)
        || first.holder() != batch.principal()
        || batch_bytes(&key, &encoded)? != bytes
    {
        return Err(KernelError::Corrupt(
            "draft batch does not bind one canonical ordered request and planner".into(),
        ));
    }
    Ok(DecodedPlanRecord {
        kind: Kind::PlanBatch,
        discriminator: key,
        members,
    })
}

pub(super) fn same_member(
    book: &BookContext,
    retained: &PlannedIntent,
    requested: &PostIntent,
    capability: &Capability,
) -> Result<bool, KernelError> {
    if retained.capability != *capability || retained.intent.approvals() != requested.approvals() {
        return Ok(false);
    }
    Ok(
        match (
            retained.intent.proposal().semantic_digest(&book.seal_key),
            requested.proposal().semantic_digest(&book.seal_key),
        ) {
            (Ok(a), Ok(b)) => a == b,
            _ => {
                retained.intent.proposal().proposal_digest()?
                    == requested.proposal().proposal_digest()?
            }
        },
    )
}

pub(super) fn storage_admission<T>(result: Outcome<T>, control: VId) -> Outcome<T> {
    match result {
        Err(KernelError::Txn(WriteTxnError::Write(fgdb::WriteError::VertexStorageAdmission {
            vid,
            source,
        }))) if vid == control => Ok(Err(usage(
            format!(
                "the atomic draft Plan record does not fit native storage: {source}; nothing was appended"
            ),
            "submit a smaller independent batch; do not split members that must be reviewed together",
        ))),
        other => other,
    }
}

/// Rehearse every existing and incoming member in order, then append the
/// incoming PostBatch as one immutable Plan record. Any refusal leaves the
/// entire draft and trunk unchanged. The key is scoped to this draft's batch
/// namespace; retries compare ordered semantic requests before re-rehearsal,
/// including after promotion or discard, under current planning authority.
pub async fn plan_batch_into_draft<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    name: &str,
    batch: PostBatch,
    req: DraftRequest,
) -> Outcome<DraftPlanned> {
    if batch.principal() != req.capability.holder() {
        return Ok(Err(denial(&Denial::NotHolder {
            holder: req.capability.holder(),
            principal: batch.principal(),
        })));
    }
    if batch.book_id() != book.book_id || batch.branch_id() != Id128::TRUNK {
        return Ok(Err(usage(
            "a draft batch plans intents for this book's trunk",
            "build every member with this book's id and the trunk branch",
        )));
    }
    for (index, intent) in batch.members().iter().enumerate() {
        if crate::asset_cost::has_basis(intent.proposal())
            && let Err(refusal) = crate::asset_cost::authorize(db, book, &req.capability)?
        {
            return Ok(Err(refusal.at("member", index)));
        }
        if (intent.proposal().class == EntryClass::REVALUATION
            || crate::revaluation::is_source_bound(intent.proposal()))
            && let Err(refusal) = crate::revaluation::authorize(db, book, &req.capability)?
        {
            return Ok(Err(refusal.at("member", index)));
        }
        if !crate::batch::batchable(intent.proposal().class) {
            return Ok(Err(usage(
                format!("draft batch member {index} has a class that cannot join one promotion"),
                "use the class's dedicated workflow; draft batches accept the same classes as PostBatch",
            )
            .at("member", index)));
        }
    }
    // This includes revocation/expiry and whole-book reach, before the draft
    // or its original outcome can be observed.
    let view = match owned_draft(db, ctx, book, &req.capability, name)? {
        Ok(view) => view,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let mut proposal = record_proposal(
        book,
        &view.body,
        Kind::PlanBatch,
        view.body.owner,
        batch.idempotency_key(),
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
    if !retained.is_empty() {
        let mut same = retained.len() == batch.members().len();
        for (old, new) in retained.iter().zip(batch.members()) {
            same &= same_member(book, old, new, &req.capability)?;
        }
        if !same {
            let row = db.vertex(evid)?.ok_or_else(|| {
                KernelError::Corrupt("a draft batch's recorded outcome vanished".into())
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
    if db.vertex(evid)?.is_some() {
        return Err(KernelError::Corrupt(
            "a live draft batch record is absent from its intent log".into(),
        ));
    }
    if view
        .intents
        .len()
        .checked_add(batch.members().len())
        .is_none_or(|n| n > fa_model::limits::MAX_BATCH_ENTRIES)
    {
        return Ok(Err(usage(
            "the complete draft would exceed max_batch_entries; nothing was appended",
            "promote this draft before planning another batch into a new draft",
        )));
    }
    let candidates: Vec<_> = batch
        .members()
        .iter()
        .map(|intent| (intent.clone(), &req.capability))
        .collect();
    let preview = match preview_ordered(db, ctx, book, &view, &candidates).await? {
        Ok(preview) => preview,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let encoded = preview.members()[view.intents.len()..]
        .iter()
        .map(|member| {
            intent_bytes(
                &member.intent,
                &req.capability,
                Some(member.entry.entry_digest),
                Some(&member.entry),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let extension = batch_bytes(batch.idempotency_key(), &encoded)?;
    if extension.len() > fa_model::limits::MAX_EXTENSION_BYTES {
        return Ok(Err(usage(
            format!(
                "the atomic draft batch needs {} bytes; max_extension_bytes is {}; nothing was appended",
                extension.len(),
                fa_model::limits::MAX_EXTENSION_BYTES
            ),
            "submit a smaller independent batch; do not split members that must be reviewed together",
        )));
    }
    proposal.extensions = vec![(fa_model::entry::DRAFT_INTENT_EXTENSION, extension)];
    if proposal.validate().is_err() {
        return Ok(Err(usage(
            "the complete reviewed draft batch exceeds the DraftControl format; nothing was appended",
            "reduce the batch's retained input size",
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
    let mut in_case = WriteBatch::new(relation::IN_CASE);
    in_case.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    in_case.add_edge(
        edge_id(relation::IN_CASE, evid, view.vid),
        evid,
        view.vid,
        vec![],
    );
    if let Err(refusal) = storage_admission(
        txn.write(db, in_case).map(Ok).map_err(KernelError::from),
        evid,
    )? {
        txn.abort();
        return Ok(Err(refusal));
    }
    Ok(storage_admission(
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

    #[test]
    fn batch_codec_preserves_order_and_requires_complete_reviewed_members() {
        let first = super::super::tests::codec_intent();
        let mut second_proposal = first.proposal().clone();
        second_proposal.idempotency_key = b"second".to_vec();
        let second = PostIntent::new(second_proposal, Vec::new()).unwrap();
        let cap = Capability::embedded(VId(7), &["post"]).unwrap();
        let encode = |intent: &PostIntent| {
            let entry = intent.proposal().clone().seal(Vec::new(), None).unwrap();
            intent_bytes(intent, &cap, Some(entry.entry_digest), Some(&entry)).unwrap()
        };
        let members = vec![encode(&second), encode(&first)];
        let bytes = batch_bytes(b"batch", &members).unwrap();
        let decoded = decode_plan_record(&bytes).unwrap();
        assert_eq!(decoded.discriminator, b"batch");
        assert_eq!(decoded.members[0].0, second);
        assert_eq!(decoded.members[1].0, first);
        for end in 0..bytes.len() {
            assert!(
                decode_plan_record(&bytes[..end]).is_err(),
                "truncated at {end}"
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_plan_record(&trailing).is_err());
        assert!(decode_plan_record(&batch_bytes(b"batch", &[]).unwrap()).is_err());
        assert!(
            decode_plan_record(&batch_bytes(b"batch", &[encode(&first), encode(&first)]).unwrap())
                .is_err()
        );
        let unreviewed = intent_bytes(&first, &cap, None, None).unwrap();
        assert!(decode_plan_record(&batch_bytes(b"batch", &[unreviewed]).unwrap()).is_err());
    }
}
