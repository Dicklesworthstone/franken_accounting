//! An exact new invoice can supply one later application in a native draft.
//! Its initial carrying value comes from its reviewed, natively validated
//! quotation. It never borrows a committed item's history or another draft's
//! proposal, and no existing carrying fold gains a staged-history shortcut.

use super::*;
use fa_model::{Entry, EntryOrigin};
use fgdb::WriteTxn;

#[derive(Clone, Copy)]
pub(super) enum Sources<'a> {
    None,
    Staged(&'a WriteTxn),
    Recorded(&'a BTreeMap<VId, Entry>),
}

pub(crate) fn fresh_source_shape(proposal: &EntryPayload) -> Result<bool, KernelError> {
    Ok(proposal.class == EntryClass::ORIGINAL
        && matches!(proposal.origin, EntryOrigin::Intent { .. })
        && proposal.branch_id == Id128::TRUNK
        && proposal.pending.is_none()
        && proposal.control.is_none()
        && proposal.supersession.is_empty()
        && proposal.extensions.is_empty()
        && proposal.legs.iter().all(|leg| leg.settles.is_empty())
        && proposal.base_totals.as_ref().is_some_and(|totals| {
            matches!(
                FxLawId::from_oid(&totals.fx_law_oid),
                Some(FxLawId::SpotClose | FxLawId::PeriodAverage)
            )
        })
        && !crate::post::requires_aggregate_basis(proposal)?)
}

fn initial_item<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    entry: &Entry,
    target: EntryRef,
    ordinal: u16,
    at: CommitSeq,
) -> Outcome<CarryingOpenItem> {
    if !fresh_source_shape(&entry.proposal)?
        || entry.proposal.book_id != book.book_id
        || entry.entry_ref(target.vid) != target
        || entry_vid(
            book.book_id,
            &entry.proposal.principal_ref.0.to_le_bytes(),
            &entry.proposal.idempotency_key,
        ) != target.vid
    {
        return Ok(Err(invalid(
            "the new carrying source is not the exact reviewed quoted Original",
        )));
    }
    let Some(leg) = entry.proposal.legs.get(usize::from(ordinal)) else {
        return Ok(Err(invalid("target ordinal is outside the original entry")));
    };
    let spec = crate::fx::book_spec_at(db, book, at)?;
    let Some(base) = leg.base_amount else {
        return Ok(Err(invalid(
            "the new foreign source has no recorded base valuation",
        )));
    };
    if leg.amount.unit == spec.base_unit
        || base.unit != spec.base_unit
        || leg.amount.mantissa <= 0
        || base.mantissa < 0
    {
        return Ok(Err(invalid(
            "the new carrying source must be a positive foreign item with its recorded functional valuation",
        )));
    }
    let mut source_hash = fgdb_crypto::Hasher::new();
    source_hash.update(b"fa:allocated-carrying-source:v1");
    source_hash.update(&target.vid.0.to_le_bytes());
    source_hash.update(&target.entry_digest);
    source_hash.update(&ordinal.to_le_bytes());
    Ok(Ok(CarryingOpenItem {
        target,
        ordinal,
        account: leg.account_ref,
        side: leg.side,
        dimensions: leg.dimension_set.clone(),
        effective_date: entry.proposal.effective_date,
        known_at: at,
        original_native: leg.amount,
        original_base: base,
        applied_native: Amount::new(leg.amount.unit, 0),
        applied_base: Amount::new(base.unit, 0),
        open_native: leg.amount,
        open_base: base,
        historical_open_base: base,
        valuation_open_base: Amount::new(base.unit, 0),
        carrying_source_digest: source_hash.finalize().0,
        valuation_route: None,
        valuation_routes_entry: None,
        valuation_routes_digest: None,
        latest_effective_date: entry.proposal.effective_date,
    }))
}

/// A source-only admission can resolve its owner's retained invoice. The
/// source payload remains private and its complete current scope is judged
/// before any derived effect or authenticated handle is returned.
pub(super) fn retained_source<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    admission: &crate::draft::DraftSourceAdmission,
    vid: VId,
) -> Outcome<Option<Entry>> {
    let entry = match admission.retained_source_entry(db, cx, book, vid)? {
        Ok(Some(entry)) => entry,
        Ok(None) => return Ok(Ok(None)),
        Err(refusal) => return Ok(Err(refusal)),
    };
    let current = match crate::policy::current_at(db, book, admission.capability())? {
        Ok(current) => current,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let scope = crate::policy::account_scope(db, book, &current)?;
    if !fresh_source_shape(&entry.proposal)?
        || entry.proposal.book_id != book.book_id
        || crate::policy::payload_reach_in_branch(
            admission.capability(),
            book,
            &entry.proposal,
            scope.as_ref(),
            fa_model::draft_branch(book.book_id, admission.name()),
        )
        .is_err()
    {
        return Ok(Ok(None));
    }
    Ok(Ok(Some(entry)))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn prepared_item<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    admission: Option<&crate::draft::DraftSourceAdmission>,
    target: EntryRef,
    ordinal: u16,
    at: CommitSeq,
    audits: Option<&mut SuccessfulHistoryAudits>,
) -> Outcome<CarryingOpenItem> {
    if db.vertex_at(target.vid, at)?.is_none()
        && let Some(admission) = admission
    {
        return match retained_source(db, cx, book, admission, target.vid)? {
            Ok(Some(entry)) => initial_item(db, book, &entry, target, ordinal, at),
            Ok(None) => Ok(Err(invalid(
                "the foreign open item is unavailable within this draft's source scope",
            ))),
            Err(refusal) => Ok(Err(refusal)),
        };
    }
    open_item_carrying_with_audits(db, cx, book, target, ordinal, at, audits)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn validated_item<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    target: EntryRef,
    ordinal: u16,
    at: CommitSeq,
    audits: Option<&mut SuccessfulHistoryAudits>,
    sources: Sources<'_>,
) -> Outcome<CarryingOpenItem> {
    if db.vertex_at(target.vid, at)?.is_none() {
        match sources {
            Sources::Staged(txn) => {
                if let Some(row) = txn.vertex(db, target.vid)? {
                    let (entry, _) = crate::post::checked_entry_staged(txn, db, &row)?;
                    return initial_item(db, book, &entry, target, ordinal, at);
                }
            }
            Sources::Recorded(entries) => {
                if let Some(entry) = entries.get(&target.vid) {
                    return initial_item(db, book, entry, target, ordinal, at);
                }
            }
            Sources::None => {}
        }
    }
    open_item_carrying_with_audits(db, cx, book, target, ordinal, at, audits)
}

/// Historical verification reconstructs only the authenticated atomic batch,
/// not the post-publication open-item fold (which already includes this relief).
/// An existing target still uses exactly the old pre-publication history.
pub(crate) fn validate_recorded_post<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    entry: &Entry,
    vid: VId,
    recorded_at: CommitSeq,
) -> Outcome<()> {
    let Some(prior) = recorded_at.0.checked_sub(1).map(CommitSeq) else {
        return Err(KernelError::Corrupt(
            "a settlement was recorded at sequence zero".into(),
        ));
    };
    let mut fresh = false;
    for application in entry.proposal.legs.iter().flat_map(|leg| &leg.settles) {
        if db.vertex_at(application.target.vid, prior)?.is_none() {
            fresh = true;
            break;
        }
    }
    if !fresh {
        return validate_post(db, cx, book, &entry.proposal, prior);
    }
    let members = match crate::batch::recorded_carrying_members(
        db,
        cx,
        book,
        entry.entry_ref(vid),
        recorded_at,
    )? {
        Ok(members) => members,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let entries: BTreeMap<_, _> = members
        .into_iter()
        .map(|entry| {
            let vid = entry_vid(
                book.book_id,
                &entry.proposal.principal_ref.0.to_le_bytes(),
                &entry.proposal.idempotency_key,
            );
            (vid, entry)
        })
        .collect();
    crate::entry_history::verify_entry_history(db, cx, book, Some(recorded_at))?;
    validate_post_with_sources(
        db,
        cx,
        book,
        &entry.proposal,
        prior,
        Sources::Recorded(&entries),
    )
}
