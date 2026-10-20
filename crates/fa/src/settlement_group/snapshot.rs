//! One authoritative observation for every leg of an atomic settlement group.
//!
//! The caller has already normalized and bounded the whole request and admitted
//! its read scope. Posting admission still precedes every storage observation.
//! A shared report avoids replaying the journal once per leg; immutable target
//! payloads and their full digests are resolved once per entry for the group.

use std::collections::BTreeMap;

use asupersync::fs::Vfs;
use fa_journal::KernelError;
use fa_journal::rows::bytes;
use fa_model::symbols::{label, property};
use fa_model::{Entry, EntryRef, Id128, Settlement};
use fa_money::{Amount, UnitId};
use fa_policy::Capability;
use fa_registers::RegisterError;
use fa_registers::open_items::{SettlementRequest, open_items_report};
use fgdb_types::VId;
use fgdb_types::context::PurposeContexts;

use super::{PreparedSettlementGroup, SettlementGroupRequest, SettlementLegAllocation, invalid};
use crate::{AsyncBook, BookError, Outcome};

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Internal only: `prepare_settlement_group` owns envelope validation,
    /// canonical ordering, disjointness, work bounds and read admission.
    pub(super) async fn prepare_settlement_group_snapshot(
        &mut self,
        cx: &PurposeContexts,
        request: SettlementGroupRequest,
        capability: &Capability,
    ) -> Outcome<PreparedSettlementGroup> {
        let book = self.context();
        let explicit: Vec<_> = request
            .proposal
            .legs
            .iter()
            .map(|leg| (leg.amount.unit, leg.amount.mantissa))
            .collect();
        if let Err(denial) = fa_policy::admit(
            capability,
            &fa_policy::Intent {
                principal: request.proposal.principal_ref,
                trunk: true,
                op: fa_policy::Op::Post,
                book: book.book_id,
                legs: &explicit,
            },
        ) {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        if let Err(refusal) = self
            .prepare_source_history(
                cx,
                request.proposal.principal_ref,
                capability,
                fa_policy::Op::Post,
                &explicit,
            )
            .await?
        {
            return Ok(Err(refusal));
        }
        let book = self.context();
        let query = cx.query();
        query.checkpoint().map_err(BookError::Context)?;
        query.with_restriction(|| {
            let at = self.db.frontier().map_err(KernelError::from)?;
            if let Err(denial) = fa_policy::current(capability, at) {
                return Ok(Err(fa_journal::policy::refusal(&denial)));
            }
            if let Err(refusal) =
                fa_journal::policy::capability_admitted(&self.db, book, capability)?
            {
                return Ok(Err(refusal));
            }
            // Read authority is whole-book, even when the caller selects only
            // one account. All currencies and both application directions are
            // evaluated at this same sequence, never at a fresh HEAD per leg.
            let report = match open_items_report(&self.db, book, None, Some(at)) {
                Ok(report) => report,
                Err(RegisterError::InvalidSelection(message)) => return Ok(Err(invalid(message))),
                Err(error) => return Err(error.into()),
            };
            query.checkpoint().map_err(BookError::Context)?;
            let index = match report.settlement_index() {
                Ok(index) => index,
                Err(RegisterError::InvalidSelection(message)) => return Ok(Err(invalid(message))),
                Err(error) => return Err(error.into()),
            };
            query.checkpoint().map_err(BookError::Context)?;
            let mut proposal = request.proposal.clone();
            let mut allocations = Vec::with_capacity(request.payments.len());
            let mut entries = BTreeMap::<VId, (Entry, EntryRef)>::new();
            for selection in &request.payments {
                query.checkpoint().map_err(BookError::Context)?;
                let ordinal = usize::from(selection.payment_leg);
                let applying = &request.proposal.legs[ordinal];
                let demand = SettlementRequest {
                    account: applying.account_ref,
                    unit_id: applying.amount.unit.0,
                    side: applying.side,
                    amount: applying.amount.mantissa,
                    effective_date: request.proposal.effective_date,
                    targets: selection.targets.clone(),
                };
                // Keep the same allocator as single-leg preparation: exact
                // native amounts, oldest-first order and all-target validation.
                let allocation = match index.plan_settlement(&demand) {
                    Ok(allocation) => allocation,
                    Err(RegisterError::InvalidSelection(message)) => {
                        return Ok(Err(invalid(message)));
                    }
                    Err(error) => return Err(error.into()),
                };
                if allocation.allocations.is_empty() {
                    return Ok(Err(invalid(
                        "no selected item has an open amount; no payment was prepared",
                    )));
                }
                // Validate even targets assigned zero. Reuse the immutable
                // payload and digest when distinct selections name different
                // legs of the same entry; never reuse an allocation witness.
                for (vid, target_ordinal) in &allocation.request.targets {
                    query.checkpoint().map_err(BookError::Context)?;
                    if let std::collections::btree_map::Entry::Vacant(slot) = entries.entry(*vid) {
                        let row = self
                            .db
                            .vertex_at(*vid, at)
                            .map_err(KernelError::from)?
                            .filter(|row| row.labels.contains(&label::ENTRY))
                            .ok_or_else(|| {
                                KernelError::Corrupt("open-item target payload is missing".into())
                            })?;
                        let entry =
                            Entry::decode(&bytes(&row, property::FA_PAYLOAD, "settlement target")?)
                                .map_err(KernelError::from)?;
                        if entry.proposal.book_id != book.book_id
                            || entry.proposal.branch_id != Id128::TRUNK
                        {
                            return Err(KernelError::Corrupt(
                                "open-item target belongs to another coordinate".into(),
                            )
                            .into());
                        }
                        let reference = entry.entry_ref(*vid);
                        slot.insert((entry, reference));
                    }
                    let (entry, _) = entries.get(vid).ok_or_else(|| {
                        KernelError::Corrupt("resolved settlement target is missing".into())
                    })?;
                    let leg = entry
                        .proposal
                        .legs
                        .get(usize::from(*target_ordinal))
                        .ok_or_else(|| {
                            KernelError::Corrupt("open-item target ordinal is missing".into())
                        })?;
                    if leg.dimension_set != applying.dimension_set {
                        return Ok(Err(invalid(
                            "settlement target dimensions differ from the applying leg",
                        )));
                    }
                }
                proposal.legs[ordinal].settles = allocation
                    .allocations
                    .iter()
                    .map(|part| {
                        let (_, target) = entries.get(&part.entry).ok_or_else(|| {
                            KernelError::Corrupt("allocation has no resolved target digest".into())
                        })?;
                        Ok(Settlement {
                            target: *target,
                            ordinal: part.ordinal,
                            amount: Amount::new(UnitId(demand.unit_id), part.amount),
                        })
                    })
                    .collect::<Result<Vec<_>, KernelError>>()?;
                allocations.push(SettlementLegAllocation {
                    payment_leg: selection.payment_leg,
                    allocation,
                });
            }
            // This is still read-only advice. The complete entry, approvals,
            // current authority and stale-basis gate are judged by the existing
            // kernel rehearsal and authenticated PostPlan commit paths.
            if let Err(error) = proposal.validate() {
                return Ok(Err(invalid(error.to_string())));
            }
            query.checkpoint().map_err(BookError::Context)?;
            Ok(Ok(PreparedSettlementGroup {
                request,
                proposal,
                allocations,
                known_at: at,
            }))
        })
    }
}
