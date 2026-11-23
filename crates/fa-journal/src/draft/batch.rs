//! Atomic additions to an ordered draft. One Plan record binds the complete
//! batch, so neither publication nor replay can expose only some members.

use super::*;

const BATCH_VERSION: u16 = 4;
// V5 is the dedicated correction-pair record. Automatic event selections
// need their own framing: V4 makes no complete-catalog claim.
const AUTOMATIC_BATCH_VERSION: u16 = 6;

pub(super) struct DecodedPlanRecord {
    pub(super) kind: Kind,
    pub(super) discriminator: Vec<u8>,
    pub(super) members: Vec<DecodedIntent>,
    pub(super) automatic_event: Option<VId>,
}

fn batch_bytes(key: &[u8], members: &[Vec<u8>]) -> Result<Vec<u8>, KernelError> {
    let mut w = Writer::new();
    w.u16(BATCH_VERSION).bytes(key).list(members, |w, bytes| {
        w.bytes(bytes);
    });
    Ok(w.finish()?)
}

fn automatic_batch_bytes(
    key: &[u8],
    event: VId,
    members: &[Vec<u8>],
) -> Result<Vec<u8>, KernelError> {
    let mut w = Writer::new();
    w.u16(AUTOMATIC_BATCH_VERSION)
        .bytes(key)
        .u128(event.0)
        .list(members, |w, bytes| {
            w.bytes(bytes);
        });
    Ok(w.finish()?)
}

/// V1--V3 retain their original single-intent interpretation. V4 contains a
/// batch key and an ordered list of complete V3 intents, including the exact
/// reviewed entries. V6 additionally retains the automatic event selection;
/// decoding rechecks its original AutomaticRules profile. The outer record
/// is the publication/identity boundary in both versions.
pub(super) fn decode_plan_record(bytes: &[u8]) -> Result<DecodedPlanRecord, KernelError> {
    if bytes.get(..2) == Some(correction::CORRECTION_VERSION.to_le_bytes().as_slice()) {
        return correction::decode_record(bytes);
    }
    let automatic = bytes.get(..2) == Some(AUTOMATIC_BATCH_VERSION.to_le_bytes().as_slice());
    if !automatic && bytes.get(..2) != Some(BATCH_VERSION.to_le_bytes().as_slice()) {
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
            automatic_event: None,
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
    let automatic_event = if automatic {
        Some(VId(r.u128("draft_batch.event").map_err(decode)?))
    } else {
        None
    };
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
    // Retain the original typed intent kind while checking the shared shape
    // law: nonempty, bounded, common principal/book/branch and distinct keys.
    // RuleDerived members require the draft-only execution profile.
    let intents = members.iter().map(|member| member.0.clone()).collect();
    let batch = match automatic_event {
        Some(event) => PostBatch::automatic_rules(event, key.clone(), intents),
        None => PostBatch::for_draft(key.clone(), intents),
    }
    .map_err(intent_error)?;
    let canonical = match automatic_event {
        Some(event) => automatic_batch_bytes(&key, event, &encoded)?,
        None => batch_bytes(&key, &encoded)?,
    };
    let first = &members[0].1;
    if members.iter().any(|member| &member.1 != first)
        || first.holder() != batch.principal()
        || canonical != bytes
    {
        return Err(KernelError::Corrupt(
            "draft batch does not bind one canonical ordered request and planner".into(),
        ));
    }
    Ok(DecodedPlanRecord {
        kind: Kind::PlanBatch,
        discriminator: key,
        members,
        automatic_event,
    })
}

/// A complete automatic group bound to its exact place in an ordered draft.
/// Only the draft's retained record decoder and admitted incoming request
/// construct these proofs. Direct and portable batch callers cannot supply
/// one to the public posting API.
#[derive(Clone, Debug)]
pub(crate) struct AutomaticDraftGroup {
    first: usize,
    batch: PostBatch,
    capability: Capability,
}

impl AutomaticDraftGroup {
    pub(crate) const fn first(&self) -> usize {
        self.first
    }

    pub(crate) fn batch(&self) -> &PostBatch {
        &self.batch
    }

    pub(crate) fn capability(&self) -> &Capability {
        &self.capability
    }

    pub(crate) fn binds(&self, batch: &PostBatch, capabilities: &[Capability]) -> bool {
        let Some(end) = self.first.checked_add(self.batch.members().len()) else {
            return false;
        };
        self.batch.automatic_event().is_some()
            && batch.members().get(self.first..end) == Some(self.batch.members())
            && capabilities.get(self.first..end).is_some_and(|members| {
                members
                    .iter()
                    .all(|capability| capability == &self.capability)
            })
    }

    pub(super) fn incoming(
        first: usize,
        batch: &PostBatch,
        capability: &Capability,
    ) -> Option<Self> {
        batch.automatic_event().map(|_| Self {
            first,
            batch: batch.clone(),
            capability: capability.clone(),
        })
    }
}

fn retained_record<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    view: &DraftView,
    planned: &PlannedIntent,
) -> Result<DecodedPlanRecord, KernelError> {
    // A Plan record remains directly readable after reopen. Its original
    // birth is authenticated by historical point reads below, without the
    // journal/delta hydration required by fresh execution's history checks.
    let at = db.frontier()?;
    let row = db
        .vertex_at(planned.record, at)?
        .ok_or_else(|| KernelError::Corrupt("a draft Plan record is absent".into()))?;
    let entry = crate::entry_storage::decode_at(db, &row, at)?;
    let [(tag, bytes)] = entry.proposal.extensions.as_slice() else {
        return Err(KernelError::Corrupt(
            "a draft Plan record lacks its sole retained request".into(),
        ));
    };
    if *tag != fa_model::entry::DRAFT_INTENT_EXTENSION {
        return Err(KernelError::Corrupt(
            "a draft Plan record has another extension".into(),
        ));
    }
    let decoded = decode_plan_record(bytes)?;
    if row.created_at != planned.recorded_at
        || !row.labels.contains(&label::ENTRY)
        || !crate::outcome::original(db, &row)?
        || !crate::entry_storage::mirrors_match(&row, &entry)?
        || entry.proposal.class != EntryClass::DRAFT_CONTROL
        || entry.proposal.principal_ref != view.body.owner
        || entry.proposal.book_id != book.book_id
        || entry.proposal.branch_id != Id128::TRUNK
        || entry.proposal.origin
            != (EntryOrigin::Control {
                control_kind: ControlKind::DRAFT_TRANSITION,
                spec_body_digest: view.body.digest()?,
            })
        || !entry.proposal.legs.is_empty()
        || !entry.approvals.is_empty()
        || entry.plan_certificate.is_some()
        || record_vid(book, &entry.proposal) != planned.record
        || entry.proposal.idempotency_key
            != record_key(decoded.kind, view.vid, &decoded.discriminator)
        || !matches!(
            &entry.proposal.control,
            Some(ControlPayload::LifecycleTransition {
                object_ref, from: 1, to: 1, proof_refs, reason_code: 0,
            }) if *object_ref == view.vid && proof_refs.is_empty()
        )
        || decoded.members.iter().any(|(intent, capability, ..)| {
            capability.holder() != view.body.owner
                || intent.proposal().principal_ref != view.body.owner
                || intent.proposal().book_id != book.book_id
                || intent.proposal().branch_id != Id128::TRUNK
        })
    {
        return Err(KernelError::Corrupt(
            "a retained draft group differs from its original Plan identity".into(),
        ));
    }
    Ok(decoded)
}

/// Recover complete groups from their immutable Plan records, never from a
/// heuristic over Rule origins. The flattened public DraftView remains the
/// same API for older records and for ordinary source-dependent intents.
pub(super) fn automatic_groups<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    view: &DraftView,
) -> Result<Vec<AutomaticDraftGroup>, KernelError> {
    let mut groups = Vec::new();
    let mut first = 0;
    while first < view.intents.len() {
        let planned = &view.intents[first];
        let length = view.intents[first..]
            .iter()
            .take_while(|member| member.record == planned.record)
            .count();
        let decoded = retained_record(db, book, view, planned)?;
        if decoded.members.len() != length
            || decoded
                .members
                .iter()
                .zip(&view.intents[first..first + length])
                .any(|((intent, capability, digest, entry), retained)| {
                    retained.recorded_at != planned.recorded_at
                        || retained.intent != *intent
                        || retained.capability != *capability
                        || retained.resolved_entry_digest != *digest
                        || retained.resolved_entry != *entry
                })
        {
            return Err(KernelError::Corrupt(
                "a draft's flattened members differ from their complete retained group".into(),
            ));
        }
        if let Some(event) = decoded.automatic_event {
            let batch = PostBatch::automatic_rules(
                event,
                decoded.discriminator,
                decoded.members.into_iter().map(|member| member.0).collect(),
            )
            .map_err(intent_error)?;
            groups.push(AutomaticDraftGroup {
                first,
                batch,
                capability: planned.capability.clone(),
            });
        }
        first += length;
    }
    Ok(groups)
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
    if let Err(r) = check_name(name) {
        return Ok(Err(r));
    }
    if let Err(r) = admit(db, book, &req.capability, Kind::PlanBatch, name)? {
        return Ok(Err(r));
    }
    for (index, intent) in batch.members().iter().enumerate() {
        if let Err(refusal) = crate::post::authorize_request(
            db,
            book,
            &crate::post::PostRequest {
                proposal: intent.proposal().clone(),
                approvals: intent.approvals().to_vec(),
                capability: req.capability.clone(),
                plan_certificate: None,
            },
            planning_admission(book, name),
        )? {
            return Ok(Err(refusal.at("member", index)));
        }
    }
    // Container ownership and member history are read only after every batch
    // member's payload reach and ceilings have been admitted (FA-INV-10).
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
        let recorded = retained_record(db, book, &view, retained[0])?;
        let mut same = retained.len() == batch.members().len()
            && recorded.automatic_event == batch.automatic_event();
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
    if let Some(row) = db.vertex(evid)? {
        if !crate::entry_storage::has_class_mirror(&row, EntryClass::DRAFT_CONTROL) {
            return Ok(Err(crate::outcome::key_conflict()));
        }
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
    let group = AutomaticDraftGroup::incoming(view.intents.len(), &batch, &req.capability);
    let preview = match preview_ordered(db, ctx, book, &view, &candidates, group).await? {
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
    let extension = match batch.automatic_event() {
        Some(event) => automatic_batch_bytes(batch.idempotency_key(), event, &encoded)?,
        None => batch_bytes(batch.idempotency_key(), &encoded)?,
    };
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
    if let Err(refusal) = witness_fresh_record(&mut txn, db, ctx, book, &proposal, evid).await? {
        txn.abort();
        return Ok(Err(refusal));
    }
    let entry = proposal.clone().seal(Vec::new(), None)?;
    let mut in_case = WriteBatch::new(relation::IN_CASE);
    in_case.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    crate::outcome::stage_control(&mut in_case, &entry, evid)?;
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

    fn codec_rule(version: u8, event: VId, key: &[u8]) -> PostIntent {
        let mut proposal = super::super::tests::codec_intent().proposal().clone();
        let inputs = vec![0; 4];
        proposal.origin = EntryOrigin::Rule {
            rule_version_oid: fa_model::Oid([version; 32]),
            event_ref: event,
            inputs_digest: domain_digest(b"fa:canon-inputs:v1", &[&inputs]),
        };
        proposal.idempotency_key = key.to_vec();
        proposal.extensions = vec![(fa_model::entry::RULE_INPUTS_EXTENSION, inputs)];
        PostIntent::rule_derived(proposal, Vec::new()).unwrap()
    }

    fn reviewed(intent: &PostIntent, capability: &Capability) -> Vec<u8> {
        let entry = intent.proposal().clone().seal(Vec::new(), None).unwrap();
        intent_bytes(intent, capability, Some(entry.entry_digest), Some(&entry)).unwrap()
    }

    #[test]
    fn automatic_v6_codec_binds_event_profile_order_and_complete_reviewed_entries() {
        let event = VId(13);
        let alpha = codec_rule(1, event, b"alpha");
        let omega = codec_rule(2, event, b"omega");
        let capability = Capability::embedded(VId(7), &["post"]).unwrap();
        let members = vec![reviewed(&alpha, &capability), reviewed(&omega, &capability)];
        let bytes = automatic_batch_bytes(b"group", event, &members).unwrap();
        // Independent framing pins V6 without regenerating any older record.
        let mut expected = 6_u16.to_le_bytes().to_vec();
        expected.extend_from_slice(&5_u32.to_le_bytes());
        expected.extend_from_slice(b"group");
        expected.extend_from_slice(&event.0.to_le_bytes());
        expected.extend_from_slice(&2_u32.to_le_bytes());
        for member in &members {
            expected.extend_from_slice(&u32::try_from(member.len()).unwrap().to_le_bytes());
            expected.extend_from_slice(member);
        }
        assert_eq!(bytes, expected);
        let decoded = decode_plan_record(&bytes).unwrap();
        assert_eq!(decoded.automatic_event, Some(event));
        assert_eq!(decoded.discriminator, b"group");
        assert_eq!(decoded.members[0].0, alpha);
        assert_eq!(decoded.members[1].0, omega);
        assert!(decoded.members.iter().all(|member| member.3.is_some()));
        let explicit = decode_plan_record(&batch_bytes(b"group", &members).unwrap()).unwrap();
        assert_eq!(explicit.automatic_event, None);
        assert_eq!(explicit.members, decoded.members);
        for end in 0..bytes.len() {
            assert!(
                decode_plan_record(&bytes[..end]).is_err(),
                "truncated at {end}"
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_plan_record(&trailing).is_err());
        assert!(
            decode_plan_record(&automatic_batch_bytes(b"group", VId(14), &members).unwrap())
                .is_err()
        );
        assert!(decode_plan_record(&automatic_batch_bytes(b"group", event, &[]).unwrap()).is_err());
        let duplicate_version = codec_rule(1, event, b"different-key");
        assert!(
            decode_plan_record(
                &automatic_batch_bytes(
                    b"group",
                    event,
                    &[
                        reviewed(&alpha, &capability),
                        reviewed(&duplicate_version, &capability)
                    ],
                )
                .unwrap()
            )
            .is_err()
        );
        let ordinary = super::super::tests::codec_intent();
        assert!(
            decode_plan_record(
                &automatic_batch_bytes(b"group", event, &[reviewed(&ordinary, &capability)],)
                    .unwrap()
            )
            .is_err()
        );
        let unreviewed = intent_bytes(&alpha, &capability, None, None).unwrap();
        assert!(
            decode_plan_record(&automatic_batch_bytes(b"group", event, &[unreviewed]).unwrap())
                .is_err()
        );
        let changed_planner = capability
            .clone()
            .with_ceiling(alpha.proposal().legs[0].amount.unit, 100)
            .unwrap();
        assert!(
            decode_plan_record(
                &automatic_batch_bytes(
                    b"group",
                    event,
                    &[
                        reviewed(&alpha, &capability),
                        reviewed(&omega, &changed_planner)
                    ],
                )
                .unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn automatic_group_proof_cannot_change_offset_member_order_or_retained_capability() {
        let event = VId(13);
        let alpha = codec_rule(1, event, b"alpha");
        let omega = codec_rule(2, event, b"omega");
        let ordinary = super::super::tests::codec_intent();
        let capability = Capability::embedded(VId(7), &["post"]).unwrap();
        let automatic = PostBatch::automatic_rules(
            event,
            b"group".to_vec(),
            vec![alpha.clone(), omega.clone()],
        )
        .unwrap();
        let proof = AutomaticDraftGroup::incoming(1, &automatic, &capability).unwrap();
        let combined = PostBatch::for_draft(
            b"promotion".to_vec(),
            vec![ordinary.clone(), alpha.clone(), omega.clone()],
        )
        .unwrap();
        let capabilities = vec![capability.clone(); 3];
        assert!(proof.binds(&combined, &capabilities));
        let reordered =
            PostBatch::for_draft(b"promotion".to_vec(), vec![ordinary, omega, alpha]).unwrap();
        assert!(!proof.binds(&reordered, &capabilities));
        assert!(!proof.binds(&combined, &capabilities[..2]));
        let mut altered = capabilities.clone();
        altered[2] = capability
            .clone()
            .with_ceiling(combined.members()[0].proposal().legs[0].amount.unit, 100)
            .unwrap();
        assert!(!proof.binds(&combined, &altered));
        assert!(
            !AutomaticDraftGroup::incoming(0, &automatic, &capability)
                .unwrap()
                .binds(&combined, &capabilities)
        );
        assert!(AutomaticDraftGroup::incoming(0, &combined, &capability).is_none());
    }

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
