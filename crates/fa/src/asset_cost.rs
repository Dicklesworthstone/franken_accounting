//! Immutable acquisition schedules and native cumulative asset charges.

use asupersync::fs::Vfs;
use fa_model::{ApprovalRef, EntryPayload};
use fa_policy::{Capability, Op};
use fgdb_types::CommitSeq;
use fgdb_types::context::PurposeContexts;

use crate::{AsyncBook, Outcome};

pub use fa_journal::asset_cost::{
    AssetChargeBasis, AssetChargeRequest, AssetCostKind, AssetRegister, AssetRegisterRow,
    AssetScheduleRecorded, AssetScheduleRequest, AssetScheduleSpec, PreparedAssetCharge,
    StoredAssetSchedule, asset_schedule_proposal,
};

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Asset reports prove immutable source history even for HEAD. General
    /// report preflight may omit hydration for a current-schema checkpoint,
    /// so explicitly load the retained prefix after admitting current Read.
    async fn prepare_asset_history(
        &mut self,
        cx: &PurposeContexts,
        known_at: Option<CommitSeq>,
        capability: &Capability,
    ) -> Outcome<()> {
        if let Err(refusal) = self
            .prepare_report_history(cx, capability.holder(), capability, known_at)
            .await?
        {
            return Ok(Err(refusal));
        }
        if let Err(refusal) = fa_journal::scratch::ensure_history(&mut self.db, cx).await? {
            return Ok(Err(refusal));
        }
        // Each native reader repeats current capability and selected-prefix
        // admission before its fold, including after this awaited hydration.
        Ok(Ok(()))
    }

    pub async fn create_asset_schedule(
        &mut self,
        cx: &PurposeContexts,
        request: AssetScheduleRequest,
        capability: &Capability,
    ) -> Outcome<AssetScheduleRecorded> {
        if let Err(refusal) = self
            .prepare_source_history(cx, request.principal, capability, Op::SchemaChange, &[])
            .await?
        {
            return Ok(Err(refusal));
        }
        Ok(fa_journal::asset_cost::create_asset_schedule(
            &mut self.db,
            cx,
            &self.context,
            capability,
            request,
        )
        .await?)
    }

    /// Publish the exact review and its current approvals. Immutable terms
    /// cannot be amended or redeclared under another name for the same leg.
    pub async fn create_asset_schedule_proposal(
        &mut self,
        cx: &PurposeContexts,
        proposal: EntryPayload,
        approvals: Vec<ApprovalRef>,
        capability: &Capability,
    ) -> Outcome<AssetScheduleRecorded> {
        if let Err(refusal) = self
            .prepare_source_history(
                cx,
                proposal.principal_ref,
                capability,
                Op::SchemaChange,
                &[],
            )
            .await?
        {
            return Ok(Err(refusal));
        }
        Ok(fa_journal::asset_cost::create_asset_schedule_proposal(
            &mut self.db,
            cx,
            &self.context,
            capability,
            proposal,
            approvals,
        )
        .await?)
    }

    pub async fn asset_schedules(
        &mut self,
        cx: &PurposeContexts,
        known_at: Option<CommitSeq>,
        capability: &Capability,
    ) -> Outcome<Vec<StoredAssetSchedule>> {
        if let Err(refusal) = self.prepare_asset_history(cx, known_at, capability).await? {
            return Ok(Err(refusal));
        }
        self.query(cx, |db, book| {
            let at = known_at.unwrap_or(db.frontier().map_err(fa_journal::KernelError::from)?);
            Ok(fa_journal::asset_cost::asset_schedules(
                db, cx, book, capability, at,
            )?)
        })
    }

    /// Inspect acquisition cost, net recognition and remaining basis with Read
    /// authority only. The selected coordinate includes all recorded effects;
    /// it does not filter them by financial effective date.
    pub async fn asset_register(
        &mut self,
        cx: &PurposeContexts,
        known_at: Option<CommitSeq>,
        capability: &Capability,
    ) -> Outcome<AssetRegister> {
        if let Err(refusal) = self.prepare_asset_history(cx, known_at, capability).await? {
            return Ok(Err(refusal));
        }
        self.query(cx, |db, book| {
            let at = known_at.unwrap_or(db.frontier().map_err(fa_journal::KernelError::from)?);
            Ok(fa_journal::asset_cost::asset_register(
                db, cx, book, capability, at,
            )?)
        })
    }

    /// Compute a source-bound charge under current authority. The empty
    /// template identifies exact retries before fresh-source/no-op calculation.
    /// Use PreparedAssetCharge::proposal with ordinary plan and commit_plan.
    pub async fn prepare_asset_charge(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        request: &AssetChargeRequest,
        template: &EntryPayload,
    ) -> Outcome<PreparedAssetCharge> {
        if let Err(refusal) = self
            .prepare_source_history(cx, template.principal_ref, capability, Op::Post, &[])
            .await?
        {
            return Ok(Err(refusal));
        }
        Ok(fa_journal::asset_cost::prepare_asset_charge(
            &self.db,
            cx,
            &self.context,
            capability,
            request,
            template,
        )?)
    }
}
