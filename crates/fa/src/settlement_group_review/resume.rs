//! Live revalidation is separate from transport validation and from retry.

use super::*;

use asupersync::fs::Vfs;
use fa_model::ApprovalRef;
use fa_policy::Capability;
use fgdb_types::context::PurposeContexts;

use crate::{AsyncBook, BookError, Outcome, SettlementGroupPostPlan};

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Revalidate a portable review under current read/post authority. Only
    /// known-at may advance: exact sealed proposal, full applied-target digests,
    /// eligible targets, FIFO order, before/after and unapplied amounts must
    /// match. Even competing consumption which leaves enough capacity requires
    /// new review. No journal object is published and no old history is proved.
    pub async fn refresh_settlement_group_review(
        &mut self,
        cx: &PurposeContexts,
        review: &SettlementGroupReview,
        capability: &Capability,
    ) -> Outcome<PreparedSettlementGroup> {
        if let Err(denial) = fa_policy::admit_read(
            capability,
            review.proposal().principal_ref,
            self.context().book_id,
        ) {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        cx.query().checkpoint().map_err(BookError::Context)?;
        let request = match review.request() {
            Ok(request) => request,
            Err(error) => {
                return Ok(Err(fa_journal::Refusal::new(
                    fa_journal::refusal::code::STRUCTURE,
                    fa_journal::exit::USAGE,
                    error.to_string(),
                    "fa:settlement-group-review:v1 (bounded canonical request)",
                    "load an unchanged review exported from settlement-group preparation",
                )));
            }
        };
        let fresh = match self
            .prepare_settlement_group(cx, request, capability)
            .await?
        {
            Ok(fresh) => fresh,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if fresh.known_at() < review.known_at()
            || fresh.proposal() != review.proposal()
            || fresh.allocations().len() != review.allocations().len()
            || fresh
                .allocations()
                .iter()
                .zip(review.allocations())
                .any(|(new, old)| {
                    new.payment_leg != old.payment_leg
                        || new.allocation.request != old.allocation.request
                        || new.allocation.allocations != old.allocation.allocations
                        || new.allocation.unapplied != old.allocation.unapplied
                })
        {
            return Ok(Err(fa_journal::Refusal::new(
                fa_journal::refusal::code::PLAN_INVALIDATED,
                fa_journal::exit::CONFLICT,
                "the complete payment or its saved group allocation observations changed",
                "plan §5.7 / §10.4 (exact reviewed effects and current approval applicability)",
                "review a fresh group and obtain required approvals; after an attempted commit retry the saved PostPlan instead",
            )));
        }
        Ok(Ok(fresh))
    }

    /// Resume a saved review after restart or approval publication, then
    /// rehearse the complete unchanged entry through the real kernel. Approvals
    /// must bind review.proposal().proposal_digest(), never review.digest().
    /// Save the returned PostPlan BEFORE publication for exact uncertain retries.
    /// This never calls the convenience replanner or commits a payment.
    pub async fn plan_settlement_group_review(
        &mut self,
        cx: &PurposeContexts,
        review: &SettlementGroupReview,
        approvals: Vec<ApprovalRef>,
        capability: &Capability,
    ) -> Outcome<SettlementGroupPostPlan> {
        let fresh = match self
            .refresh_settlement_group_review(cx, review, capability)
            .await?
        {
            Ok(fresh) => fresh,
            Err(refusal) => return Ok(Err(refusal)),
        };
        self.plan_prepared_settlement_group(cx, fresh, approvals, capability)
            .await
    }
}
