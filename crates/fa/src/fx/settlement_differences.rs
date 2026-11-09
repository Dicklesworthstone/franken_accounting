//! Source-derived FX settlements with explicitly classified cash adjustments.
//! These methods preserve the ordinary preparation/plan/commit protocol and
//! the confined draft source boundary. They never infer an adjustment amount.

use asupersync::fs::Vfs;
use fa_model::EntryPayload;
use fa_money::rate::ArithmeticBudget;
use fa_policy::Capability;
use fgdb_types::context::PurposeContexts;

use super::{
    FxSettlementWithDifferencesRequest, MAX_FX_SETTLEMENT_ITEMS, PreparedFxSettlement,
    PreparedFxSettlementGroup, invalid,
};
use crate::{AsyncBook, BookError, Outcome};

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Derive carrying relief and realized FX from authenticated sources while
    /// keeping each declared Discount, Writeoff or BankCharge separate. The
    /// settlement amount is actual base-currency cash; the retained rate must
    /// reproduce cash plus reductions and the direction-specific bank charges.
    pub async fn prepare_fx_settlement_with_differences(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        request: &FxSettlementWithDifferencesRequest,
        template: EntryPayload,
        budget: &mut ArithmeticBudget<'_, impl Sized>,
    ) -> Outcome<PreparedFxSettlement> {
        if let Err(refusal) = self
            .prepare_fx_settlement_source(
                cx,
                capability,
                None,
                request.settlement.rate_document,
                &template,
            )
            .await?
        {
            return Ok(Err(refusal));
        }
        let result = fa_journal::carrying::prepare_fx_settlement_with_differences(
            &self.db,
            cx,
            &self.context,
            capability,
            request,
            template,
            budget,
        )?;
        if let Err(refusal) =
            self.authorize_fx_read(cx, capability, capability.holder(), true, None)?
        {
            return Ok(Err(refusal));
        }
        Ok(result)
    }

    /// Prepare a bounded group at one carrying prefix. Each item declares its
    /// own actual cash and adjustments; every item shares the same retained
    /// Settlement rate. Empty adjustment lists retain the legacy effect bytes.
    pub async fn prepare_fx_settlement_group_with_differences(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        requests: &[FxSettlementWithDifferencesRequest],
        template: EntryPayload,
        budget: &mut ArithmeticBudget<'_, impl Sized>,
    ) -> Outcome<PreparedFxSettlementGroup> {
        if let Err(refusal) =
            self.authorize_fx_read(cx, capability, template.principal_ref, true, None)?
        {
            return Ok(Err(refusal));
        }
        if requests.is_empty() || requests.len() > MAX_FX_SETTLEMENT_ITEMS {
            return Ok(Err(invalid(
                "FX group is empty or exceeds the entry leg work bound",
            )));
        }
        let rate_document = requests[0].settlement.rate_document;
        if requests
            .iter()
            .any(|request| request.settlement.rate_document != rate_document)
        {
            return Ok(Err(invalid(
                "FX group requires one shared Settlement Rate document",
            )));
        }
        if let Err(refusal) = self
            .prepare_fx_settlement_source(cx, capability, None, rate_document, &template)
            .await?
        {
            return Ok(Err(refusal));
        }
        let result = fa_journal::carrying::prepare_fx_settlement_group_with_differences(
            &self.db,
            cx,
            &self.context,
            capability,
            requests,
            template,
            budget,
        )?;
        if let Err(refusal) =
            self.authorize_fx_read(cx, capability, capability.holder(), true, None)?
        {
            return Ok(Err(refusal));
        }
        Ok(result)
    }

    /// Derive only the effects admitted within the holder's own open draft.
    /// No open balance or carrying explanation escapes the source scope.
    #[allow(clippy::too_many_arguments)]
    pub async fn prepare_fx_settlement_with_differences_in_draft(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        name: &str,
        request: &FxSettlementWithDifferencesRequest,
        template: EntryPayload,
        budget: &mut ArithmeticBudget<'_, impl Sized>,
    ) -> Outcome<EntryPayload> {
        self.prepare_fx_settlement_group_with_differences_in_draft(
            cx,
            capability,
            name,
            std::slice::from_ref(request),
            template,
            budget,
        )
        .await
    }

    /// Admit every declared route and amount before hydrating the source
    /// history, then admit every generated effect again after derivation.
    #[allow(clippy::too_many_arguments)]
    pub async fn prepare_fx_settlement_group_with_differences_in_draft(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        name: &str,
        requests: &[FxSettlementWithDifferencesRequest],
        template: EntryPayload,
        budget: &mut ArithmeticBudget<'_, impl Sized>,
    ) -> Outcome<EntryPayload> {
        let admission = match self.query(cx, |db, book| {
            Ok(fa_journal::draft::admit_sources(
                db, book, capability, name,
            )?)
        })? {
            Ok(admission) => admission,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let query = cx.query();
        query.checkpoint().map_err(BookError::Context)?;
        if let Err(refusal) = query.with_restriction(|| {
            fa_journal::carrying::admit_draft_settlement_requests_with_differences(
                &mut self.db,
                cx,
                &self.context,
                &admission,
                requests,
                &template,
            )
        })? {
            return Ok(Err(refusal));
        }
        if let Err(refusal) = self
            .prepare_fx_settlement_source(
                cx,
                capability,
                Some(&admission),
                requests[0].settlement.rate_document,
                &template,
            )
            .await?
        {
            return Ok(Err(refusal));
        }
        let result = query.with_restriction(|| {
            fa_journal::carrying::prepare_fx_settlement_group_with_differences_in_draft(
                &mut self.db,
                cx,
                &self.context,
                &admission,
                requests,
                template,
                budget,
            )
        })?;
        query.checkpoint().map_err(BookError::Context)?;
        if let Err(refusal) = self.query(cx, |db, book| Ok(admission.recheck(db, book)?))? {
            return Ok(Err(refusal));
        }
        Ok(result)
    }
}
