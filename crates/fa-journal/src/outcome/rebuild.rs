//! Explicit, authorized legacy upgrade; ordinary posts never scan for keys.

use std::collections::BTreeMap;

use fa_model::symbols::relation;
use fa_policy::{Capability, Intent, Op, Reach};
use fgdb_types::context::PurposeContexts;

use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutcomeRebuildPreview {
    pub basis: CommitSeq,
    pub entries_checked: usize,
    pub outcomes_created: usize,
    pub already_covered: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutcomeRebuild {
    pub basis: CommitSeq,
    pub recorded_at: CommitSeq,
    pub entries_checked: usize,
    pub outcomes_created: usize,
    pub wrote: bool,
}

/// Owns the exact reviewed effect and its original authority. Only this module
/// can construct it; publication never accepts a caller-authored coverage claim.
#[derive(Debug)]
#[must_use]
pub struct PreparedOutcomeRebuild {
    book: Id128,
    source_root: [u8; 32],
    capability: Capability,
    preview: OutcomeRebuildPreview,
    recorded_at: Option<CommitSeq>,
    txn: Option<WriteTxn>,
}

impl PreparedOutcomeRebuild {
    #[must_use]
    pub fn preview(&self) -> &OutcomeRebuildPreview {
        &self.preview
    }

    pub fn abort(self) {
        if let Some(txn) = self.txn {
            txn.abort();
        }
    }
}

fn admit<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    capability: &Capability,
) -> Outcome<()> {
    for op in [Op::Read, Op::SchemaChange] {
        if let Err(denial) = fa_policy::admit_within(
            capability,
            &Intent {
                principal: capability.holder(),
                trunk: true,
                op,
                book: book.book_id,
                legs: &[],
            },
            &Reach::whole_book(true),
            None,
        ) {
            return Ok(Err(crate::policy::refusal(&denial)));
        }
    }
    if let Err(denial) = fa_policy::current(capability, db.frontier()?) {
        return Ok(Err(crate::policy::refusal(&denial)));
    }
    crate::policy::capability_admitted(db, book, capability)
}

fn invalidated() -> Refusal {
    Refusal::new(
        code::PLAN_INVALIDATED,
        exit::CONFLICT,
        "the outcome rebuild's reviewed prefix changed",
        "plan §5.9 (complete legacy key coverage at one exact source prefix)",
        "run `fa recover outcomes --dry-run` again and confirm its new basis",
    )
}

/// Verify all original Entry history and prepare every missing key claim plus
/// one coverage root. Collisions and native capacity failures publish nothing.
/// This explicit recovery requires whole-book Read AND SchemaChange; a normal
/// posting never broadens a capability or performs this scan implicitly.
pub async fn prepare_outcome_rebuild<V: Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capability: Capability,
) -> Outcome<PreparedOutcomeRebuild> {
    if let Err(refusal) = admit(db, book, &capability)? {
        return Ok(Err(refusal));
    }
    let query = ctx.query();
    query.checkpoint().map_err(WriteTxnError::Interrupted)?;
    let mut txn = db.begin(&ctx.txn())?;
    if let Err(refusal) = crate::policy::capability_witness(&txn, db, book, &capability)? {
        txn.abort();
        return Ok(Err(refusal));
    }
    let epoch = crate::policy::epoch_witness(&txn, db)?;
    let basis = txn.basis();
    let source_root = db.partition_root()?.0.0;
    if let Some(row) = txn.vertex(db, coverage_vid(book.book_id))? {
        if let Err(refusal) = crate::scratch::ensure_history(db, ctx).await? {
            txn.abort();
            return Ok(Err(refusal));
        }
        coverage_of(db, book, &row)?;
        txn.abort();
        return Ok(Ok(PreparedOutcomeRebuild {
            book: book.book_id,
            source_root,
            capability,
            preview: OutcomeRebuildPreview {
                basis,
                entries_checked: 0,
                outcomes_created: 0,
                already_covered: true,
            },
            recorded_at: Some(row.created_at),
            txn: None,
        }));
    }
    if let Err(refusal) = crate::scratch::ensure_history(db, ctx).await? {
        txn.abort();
        return Ok(Err(refusal));
    }
    let verified = crate::entry_history::verify_entry_history(db, ctx, book, Some(basis))?;
    let mut claims = BTreeMap::<VId, EntryClaim>::new();
    let mut stage = WriteBatch::new(relation::IN_BOOK);
    let mut outcomes_created = 0;
    for row in db.vertices_at(basis)? {
        query.checkpoint().map_err(WriteTxnError::Interrupted)?;
        if !row.labels.contains(&label::ENTRY) {
            continue;
        }
        let entry = Entry::decode(&bytes(&row, property::FA_PAYLOAD, "rebuild entry")?)?;
        if !covered_class(entry.proposal.class) {
            continue;
        }
        let ovid = entry_outcome_vid(&entry.proposal);
        if claims.contains_key(&ovid) {
            txn.abort();
            return Ok(Err(key_conflict()));
        }
        let key_vid = fa_model::entry_vid(
            book.book_id,
            &entry.proposal.principal_ref.0.to_le_bytes(),
            &entry.proposal.idempotency_key,
        );
        if key_vid != row.vid && txn.vertex_has_label(db, key_vid, label::ENTRY)?.is_some() {
            txn.abort();
            return Ok(Err(key_conflict()));
        }
        let claim = if let Some(existing) = txn.vertex(db, ovid)? {
            if !is_entry_claim(&existing) || !verify_recorded(db, &query, book, &row, &entry)? {
                txn.abort();
                return Ok(Err(key_conflict()));
            }
            claim_of(&existing)?
        } else {
            let claim = EntryClaim::new(&entry, row.vid, Some(basis))?;
            stage.create_vertex(ovid, vec![label::INTENT_OUTCOME], claim_properties(&claim)?);
            outcomes_created += 1;
            claim
        };
        claims.insert(ovid, claim);
    }
    let mut transcript = Writer::new();
    for (vid, claim) in &claims {
        transcript.u128(vid.0).bytes(&claim.canonical_bytes()?);
    }
    let key_list: Vec<_> = claims.keys().copied().collect();
    let keys_digest = keys::stage(&mut stage, book.book_id, &key_list)?;
    let mut coverage = Coverage {
        book: book.book_id,
        basis,
        source_marker: marker_at(db, basis)?,
        operator: capability.holder(),
        epoch,
        entries: u64::try_from(claims.len())
            .map_err(|_| KernelError::Corrupt("outcome count is unrepresentable".into()))?,
        claims_digest: domain_digest(b"fa:outcome-claims:v1", &[&transcript.finish()?]),
        keys_digest,
        authentication: [0; 32],
    };
    coverage.authentication = coverage.authenticate(book)?;
    stage_coverage(&mut stage, &coverage)?;
    // Full native staging is part of preparation: a capacity failure cannot
    // strand a partially upgraded book or leave a successful-looking preview.
    txn.write_ordered(db, vec![stage])?;
    Ok(Ok(PreparedOutcomeRebuild {
        book: book.book_id,
        source_root,
        capability,
        preview: OutcomeRebuildPreview {
            basis,
            entries_checked: verified.entries_checked,
            outcomes_created,
            already_covered: false,
        },
        recorded_at: None,
        txn: Some(txn),
    }))
}

/// Publish the prepared upgrade once at its exact reviewed head. No effects
/// survive an authority failure, a changed prefix or a failed native commit.
pub async fn publish_outcome_rebuild<V: Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    prepared: PreparedOutcomeRebuild,
) -> Outcome<OutcomeRebuild> {
    ctx.commit()
        .checkpoint()
        .map_err(WriteTxnError::Interrupted)?;
    if prepared.book != book.book_id {
        prepared.abort();
        return Ok(Err(invalidated()));
    }
    if let Err(refusal) = admit(db, book, &prepared.capability)? {
        prepared.abort();
        return Ok(Err(refusal));
    }
    if db.frontier()? != prepared.preview.basis || db.partition_root()?.0.0 != prepared.source_root
    {
        prepared.abort();
        return Ok(Err(invalidated()));
    }
    let PreparedOutcomeRebuild {
        preview,
        recorded_at,
        txn,
        ..
    } = prepared;
    let wrote = txn.is_some();
    let recorded_at = if let Some(txn) = txn {
        match txn.commit(db, &ctx.commit()).await {
            Ok(seq) => seq,
            Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { .. })) => {
                return Ok(Err(invalidated()));
            }
            Err(error) => return Err(error.into()),
        }
    } else {
        let Some(row) = db.vertex(coverage_vid(book.book_id))? else {
            return Ok(Err(invalidated()));
        };
        coverage_of(db, book, &row)?;
        if Some(row.created_at) != recorded_at {
            return Ok(Err(invalidated()));
        }
        row.created_at
    };
    Ok(Ok(OutcomeRebuild {
        basis: preview.basis,
        recorded_at,
        entries_checked: preview.entries_checked,
        outcomes_created: preview.outcomes_created,
        wrote,
    }))
}
