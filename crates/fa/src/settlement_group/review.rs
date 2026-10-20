//! Explicit review refresh after approval publications, never automatic retry.

use super::*;

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Revalidate an in-memory group after its complete proposal was reviewed.
    /// Only the basis may advance. The original sealed bytes, full entry
    /// handles, eligible target sets, allocation order, observed before/after
    /// amounts and unapplied balances must remain unchanged. Every selected
    /// target's eligibility and dimensions are checked again, including unused
    /// targets; unused targets' unrecorded balances are not historical claims.
    ///
    /// This requires current read+post authority through the ordinary preparer.
    /// It writes nothing, grants no approval and does not reserve capacity.
    /// Approval objects bind the COMPLETE proposal, not any intermediate
    /// single-leg preparation; the kernel still authenticates those objects.
    pub async fn refresh_settlement_group(
        &mut self,
        cx: &PurposeContexts,
        reviewed: &PreparedSettlementGroup,
        capability: &Capability,
    ) -> Outcome<PreparedSettlementGroup> {
        if let Err(denial) = fa_policy::admit_read(
            capability,
            reviewed.proposal.principal_ref,
            self.context().book_id,
        ) {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        cx.query().checkpoint().map_err(BookError::Context)?;
        let fresh = match self
            .prepare_settlement_group(cx, reviewed.request.clone(), capability)
            .await?
        {
            Ok(fresh) => fresh,
            Err(refusal) => return Ok(Err(refusal)),
        };
        // A review is not proof that its old basis existed in this history.
        // Nevertheless, never turn a newer review into an older observation.
        if fresh.known_at < reviewed.known_at
            || fresh.request != reviewed.request
            || fresh.proposal != reviewed.proposal
            || fresh.allocations.len() != reviewed.allocations.len()
            || fresh
                .allocations
                .iter()
                .zip(&reviewed.allocations)
                .any(|(new, old)| {
                    new.payment_leg != old.payment_leg
                        || new.allocation.request != old.allocation.request
                        || new.allocation.allocations != old.allocation.allocations
                        || new.allocation.unapplied != old.allocation.unapplied
                })
        {
            return Ok(Err(invalidated(
                "the complete group or its reviewed allocation observations changed",
            )));
        }
        Ok(Ok(fresh))
    }

    /// Explicitly refresh a reviewed group, then rehearse the unchanged
    /// complete proposal with its approvals. In contrast to strict
    /// plan_prepared_settlement_group, intervening approval publications may
    /// advance the basis, but never silently change any reviewed effects or
    /// allocation observations. Review the returned kernel plan before commit.
    ///
    /// After an uncertain commit, retry the SAVED PostPlan instead: refreshing
    /// would inspect balances which the successful payment already changed.
    pub async fn plan_reviewed_settlement_group(
        &mut self,
        cx: &PurposeContexts,
        reviewed: &PreparedSettlementGroup,
        approvals: Vec<ApprovalRef>,
        capability: &Capability,
    ) -> Outcome<SettlementGroupPostPlan> {
        let fresh = match self
            .refresh_settlement_group(cx, reviewed, capability)
            .await?
        {
            Ok(fresh) => fresh,
            Err(refusal) => return Ok(Err(refusal)),
        };
        self.plan_prepared_settlement_group(cx, fresh, approvals, capability)
            .await
    }
}
