//! One approval for the complete group, under an independent approver's scope.

use std::collections::BTreeMap;

use asupersync::fs::Vfs;
use fa_journal::rows::bytes;
use fa_journal::{Approved, KernelError, Refusal, exit};
use fa_model::symbols::{label, property};
use fa_model::{Entry, Id128};
use fa_policy::{Capability, Op};
use fa_registers::RegisterError;
use fgdb_types::context::PurposeContexts;

use crate::{AsyncBook, BookError, Outcome};
use super::SettlementGroupReview;

fn changed() -> Refusal {
    Refusal::new(
        fa_journal::refusal::code::PLAN_INVALIDATED, exit::CONFLICT,
        "the complete group review or its current allocation observations differ",
        "plan §5.7 / §14.3 (exact reviewed proposal and independent approval)",
        "review a fresh complete group and retain its digest independently; after an attempted commit retry its saved PostPlan instead",
    )
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Approve every applying leg and offset as ONE complete proposal. The
    /// caller supplies an independently retained review digest and current
    /// whole-book read+approve authority; posting authority is neither needed
    /// nor manufactured. The preparer cannot approve their own payment.
    ///
    /// Recompute all allocation witnesses at one fixed HEAD, checking every
    /// eligible target's dimensions (even unused targets) and every applied
    /// target's full handle. A failure on ANY leg records NO approval. Only
    /// after all legs pass does the ordinary kernel record one approval of the
    /// full proposal digest, not the review digest or intermediate proposals.
    /// Amount ceilings cover all explicit legs, including cash offsets.
    ///
    /// The unsigned review does not prove its claimed old history. Approval is
    /// not a capacity reservation or an execution certificate: planning still
    /// requires current posting authority and all economic/policy checks, and
    /// exact live revalidation of the review before kernel rehearsal.
    pub async fn approve_settlement_group_review(
        &mut self,
        cx: &PurposeContexts,
        review: &SettlementGroupReview,
        expected_review_digest: [u8; 32],
        capability: &Capability,
    ) -> Outcome<Approved> {
        let book = self.context();
        if let Err(denial) = fa_policy::admit_read(capability, capability.holder(), book.book_id) {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        cx.query().checkpoint().map_err(BookError::Context)?;
        let explicit: Vec<_> = review.proposal().legs.iter()
            .map(|leg| (leg.amount.unit, leg.amount.mantissa)).collect();
        if let Err(denial) = fa_policy::admit(capability, &fa_policy::Intent {
            principal: capability.holder(), trunk: true, op: Op::Approve,
            book: book.book_id, legs: &explicit,
        }) {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        if capability.holder() == review.proposal().principal_ref {
            return Ok(Err(Refusal::new(
                fa_journal::refusal::code::APPROVALS, exit::REFUSAL,
                "the group preparer may not approve their own proposal",
                "plan §14.3 (separation of preparer and approver)",
                "have another principal with read and approve authority review the complete saved group",
            )));
        }
        if review.proposal().book_id != book.book_id || review.proposal().branch_id != Id128::TRUNK {
            return Ok(Err(changed()));
        }
        let digest = match review.digest() {
            Ok(digest) => digest,
            Err(error) => return Ok(Err(Refusal::new(
                fa_journal::refusal::code::STRUCTURE, exit::USAGE, error.to_string(),
                "fa:settlement-group-review:v1 (bounded canonical request)",
                "supply the unchanged group review and its independently retained digest",
            ))),
        };
        if digest != expected_review_digest { return Ok(Err(changed())); }
        let query = cx.query();
        query.checkpoint().map_err(BookError::Context)?;
        // Retain the exclusive mutable book handle through publication. Native
        // reads are all pinned to one prefix; no Post capability is fabricated.
        let checked = query.with_restriction(|| -> Outcome<[u8; 32]> {
            let at = self.db.frontier().map_err(KernelError::from)?;
            if let Err(denial) = fa_policy::current(capability, at) {
                return Ok(Err(fa_journal::policy::refusal(&denial)));
            }
            if let Err(refusal) = fa_journal::policy::capability_admitted(&self.db, book, capability)? {
                return Ok(Err(refusal));
            }
            if at < review.known_at() { return Ok(Err(changed())); }
            let mut reports = BTreeMap::new();
            let mut entries = BTreeMap::new();
            for part in review.allocations() {
                query.checkpoint().map_err(BookError::Context)?;
                let request = &part.allocation.request;
                if let std::collections::btree_map::Entry::Vacant(slot) = reports.entry(request.account) {
                    let report = match fa_registers::open_items::open_items_report(
                        &self.db, book, Some(request.account), Some(at),
                    ) {
                        Ok(report) => report,
                        Err(RegisterError::InvalidSelection(_)) => return Ok(Err(changed())),
                        Err(error) => return Err(error.into()),
                    };
                    slot.insert(report);
                }
                let report = reports.get(&request.account)
                    .ok_or_else(|| KernelError::Corrupt("group review report is missing".into()))?;
                let allocation = match report.plan_settlement(request) {
                    Ok(allocation) => allocation,
                    Err(RegisterError::InvalidSelection(_)) => return Ok(Err(changed())),
                    Err(error) => return Err(error.into()),
                };
                let mut expected = part.allocation.clone(); expected.known_at = at;
                if allocation != expected { return Ok(Err(changed())); }
                let applying = &review.proposal().legs[usize::from(part.payment_leg)];
                for (vid, ordinal) in &request.targets {
                    query.checkpoint().map_err(BookError::Context)?;
                    if let std::collections::btree_map::Entry::Vacant(slot) = entries.entry(*vid) {
                        let row = self.db.vertex_at(*vid, at).map_err(KernelError::from)?
                            .filter(|row| row.labels.contains(&label::ENTRY))
                            .ok_or_else(|| KernelError::Corrupt("group review target is missing".into()))?;
                        let entry = Entry::decode(&bytes(&row, property::FA_PAYLOAD, "group review target")?)
                            .map_err(KernelError::from)?;
                        if entry.proposal.book_id != book.book_id || entry.proposal.branch_id != Id128::TRUNK {
                            return Err(KernelError::Corrupt("group review target has a foreign coordinate".into()).into());
                        }
                        slot.insert(entry);
                    }
                    let entry = entries.get(vid)
                        .ok_or_else(|| KernelError::Corrupt("resolved group review target is missing".into()))?;
                    let leg = entry.proposal.legs.get(usize::from(*ordinal))
                        .ok_or_else(|| KernelError::Corrupt("group review target ordinal is missing".into()))?;
                    if leg.dimension_set != applying.dimension_set { return Ok(Err(changed())); }
                }
                for link in &applying.settles {
                    let entry = entries.get(&link.target.vid)
                        .ok_or_else(|| KernelError::Corrupt("group application target is missing".into()))?;
                    if entry.entry_ref(link.target.vid) != link.target { return Ok(Err(changed())); }
                }
            }
            query.checkpoint().map_err(BookError::Context)?;
            Ok(Ok(review.proposal().proposal_digest().map_err(KernelError::from)?))
        })?;
        let proposal_digest = match checked {
            Ok(digest) => digest,
            Err(refusal) => return Ok(Err(refusal)),
        };
        // One ordinary approval transaction rechecks expiry/revocation and
        // binds the current policy epoch. Never publish per-leg approvals.
        self.approve(cx, capability.clone(), proposal_digest).await
    }
}
