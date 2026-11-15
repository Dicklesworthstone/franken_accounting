//! Purpose-specific source admission for a confined draft's exact reversal.
//!
//! This is not an entry reader. It returns only whether the named immutable
//! source and its entire reversal footprint are admitted, and judges the
//! derived reversal's effects before a surface can reconstruct those effects.

use fa_model::{EntryClass, Id128, PeriodRef};
use fa_policy::{Capability, Denial};
use fa_time::DateDay;
use fgdb::Database;
use fgdb_types::VId;
use fgdb_types::context::PurposeContexts;

use super::{DraftState, not_open, owned_draft};
use crate::genesis::BookContext;
use crate::refusal::{Outcome, Refusal};

/// Admit one explicitly named source for an owned, branch-confined draft's
/// exact reversal. No source payload, monetary fact or reusable Read authority
/// is returned. Missing and out-of-scope footprints both return `false`.
///
/// A closed draft may reconstruct only a source already named by a retained
/// reversal, allowing exact retries without granting fresh source derivation.
/// The native planner still decides whether the complete request is a retry.
#[allow(clippy::too_many_arguments)]
pub fn admit_reversal_source<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    name: &str,
    target: VId,
    effective_date: Option<DateDay>,
    effective_period: Option<&str>,
) -> Outcome<bool> {
    let branch = fa_model::draft_branch(book.book_id, name);
    if capability.branch() != Some(branch) {
        return Ok(Err(crate::policy::refusal(&Denial::OutOfScope {
            caveat: "branch",
            value: "reversal preparation requires confinement to this named draft".into(),
        })));
    }
    if let Err(denial) = fa_policy::require_class(capability, Some(EntryClass::REVERSAL)) {
        return Ok(Err(crate::policy::refusal(&denial)));
    }
    // Ownership, current issuance/revocation and the exact draft container
    // precede any source lookup, including retries after closure.
    let view = match owned_draft(db, ctx, book, capability, name)? {
        Ok(view) => view,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if view.state != DraftState::Open
        && !view.intents.iter().any(|planned| {
            let proposal = planned.intent.proposal();
            proposal.class == EntryClass::REVERSAL
                && proposal
                    .supersession
                    .iter()
                    .any(|link| link.target.vid == target)
        })
    {
        return Ok(Err(not_open(&view.body, view.state)));
    }
    let current = match crate::policy::current_at(db, book, capability)? {
        Ok(current) => current,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let scope = crate::policy::account_scope(db, book, &current)?;
    let txn = db.begin(&ctx.txn())?;
    let admitted = (|| {
        // Each target, predecessor and applied-to entry is admitted from its
        // public mirrors before its payload is decoded. A forged or poisoned
        // out-of-scope source therefore has the same answer as a missing one.
        if !crate::post::reversal_source_in_scope(
            &txn,
            db,
            book,
            capability,
            scope.as_ref(),
            target,
        )? {
            return Ok(Ok(false));
        }
        let Some(row) = txn.vertex(db, target)? else {
            return Ok(Ok(false));
        };
        let (entry, _) = crate::post::checked_entry(db, &row)?;
        if entry.proposal.book_id != book.book_id || entry.proposal.branch_id != Id128::TRUNK {
            return Ok(Ok(false));
        }

        // These are the exact monetary effects the surface will derive. Keep
        // only the reversal's own date/period; the original's future automatic
        // schedule is not part of an exact undo. No source fact can escape in
        // a denied amount ceiling or scope diagnostic.
        let mut derived = entry.proposal;
        derived.class = EntryClass::REVERSAL;
        derived.principal_ref = capability.holder();
        derived.effective_period = effective_period
            .map(|code| PeriodRef {
                calendar: book.calendar.id.clone(),
                code: code.to_string(),
            })
            .or_else(|| {
                if effective_date.is_none() {
                    derived.effective_period.clone()
                } else {
                    None
                }
            });
        if let Some(date) = effective_date {
            derived.effective_date = date;
        }
        for leg in &mut derived.legs {
            leg.side = match leg.side {
                fa_money::Side::Debit => fa_money::Side::Credit,
                fa_money::Side::Credit => fa_money::Side::Debit,
            };
            leg.settles.clear();
        }
        derived.extensions.clear();
        match crate::post::authorize_effects_in_branch(
            db,
            book,
            capability,
            capability.holder(),
            &derived,
            true,
            branch,
        )? {
            Ok(_) => Ok(Ok(true)),
            Err(refusal) => Ok(Err(Refusal::new(
                refusal.code,
                refusal.exit,
                "the exact reversal exceeds the capability's permitted scope or amount ceiling",
                "plan §15.2 (source-derived effects require admission before disclosure)",
                "use a capability that admits the named source and every generated reversal effect",
            ))),
        }
    })();
    txn.abort();
    admitted
}
